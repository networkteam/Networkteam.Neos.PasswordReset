<?php
namespace Networkteam\Neos\PasswordReset\Controller;

/***************************************************************
 *  (c) 2018 networkteam GmbH - all rights reserved
 ***************************************************************/

use Neos\ContentRepository\Domain\Model\NodeInterface;
use Neos\Error\Messages\Result;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\ActionResponse;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;
use Neos\Flow\Security\Authentication\Token\UsernamePassword;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Validation\Exception\InvalidValidationOptionsException;
use Neos\Flow\Validation\Validator\RegularExpressionValidator;
use Networkteam\Neos\PasswordReset\Domain\Model\PasswordResetToken;

class PasswordManagementController extends ActionController
{
    /**
     * @var \Neos\Flow\Security\Cryptography\HashService
     * @Flow\Inject
     */
    protected $hashService;

    /**
     * @var \Neos\Neos\Service\LinkingService
     * @Flow\Inject
     */
    protected $linkService;

    /**
     * @var \Neos\Neos\Domain\Service\ContentContextFactory
     * @Flow\Inject
     */
    protected $contentContextFactory;

    /**
     * @var \Neos\Flow\Security\AccountRepository
     * @Flow\Inject
     */
    protected $accountRepository;

    /**
     * @var \Networkteam\Neos\PasswordReset\Domain\Services\Mailer
     * @Flow\Inject
     */
    protected $mailer;

    /**
     * @var \Networkteam\Neos\PasswordReset\Service\TokenService
     * @Flow\Inject
     */
    protected $tokenService;

    /**
     * @var SecurityContext
     * @Flow\Inject
     */
    protected $securityContext;

    /**
     * @var \Neos\Flow\I18n\Translator
     * @Flow\Inject
     */
    protected $translator;

    /**
     * @var bool
     * @Flow\InjectConfiguration("sendResetPasswordMail")
     */
    protected $sendResetPasswordMail;

    /**
     * @var bool
     * @Flow\InjectConfiguration("sendNoAccountMail")
     */
    protected $sendNoAccountMail;

    /**
     * @var bool
     * @Flow\InjectConfiguration("passwordPattern")
     */
    protected $passwordPattern;

    /**
     * @var AuthenticationManagerInterface
     * @Flow\Inject
     */
    protected $authenticationManager;

    public function initializeRequestResetAction()
    {
        if ($this->request->hasArgument('email')) {
            $email = $this->request->getArgument('email');
            $this->request->setArgument('email', mb_strtolower($email));
        }
    }

    /**
     * @param string $email
     * @param string $redirectNodeIdentifier Identifier of node for redirect
     * @param string $resetNodeIdentifier Identifier of node containing passwort reset form
     * @throws \Neos\Eel\Exception
     * @throws \Neos\Flow\Mvc\Exception\StopActionException
     * @throws \Neos\Flow\Mvc\Exception\UnsupportedRequestTypeException
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     * @throws \Neos\Neos\Exception
     * @Flow\SkipCsrfProtection
     */
    public function requestResetAction(string $email, string $redirectNodeIdentifier, string $resetNodeIdentifier): void
    {

        $redirectNode = $this->getTargetNode($redirectNodeIdentifier);
        $resetNode = $this->getTargetNode($resetNodeIdentifier);

        if ($email === "") {
            $this->request->setArgument('resetSuccess', false);
            $this->redirectToNode($redirectNode);
        }

        $account = null;
        foreach($this->settings['authenticationProviders'] as $authenticationProviderName) {
            $account = $this->accountRepository->findByAccountIdentifierAndAuthenticationProviderName($email, $authenticationProviderName);
            if ($account !== null) {
                break;
            }
        }

        if ($account === null) {
            $this->emitAccountForRequestedResetIsNotFound($email, $redirectNode);

            if ($this->sendNoAccountMail) {
                $this->mailer->sendNoAccountMail($email, $resetNode);
            }
        } elseif (!$account->isActive()) {
            $this->emitAccountForRequestedResetIsInactive($account, $this->request, $this->response, $resetNode);
        } else {
            $token = $this->tokenService->createPasswordResetTokenForAccount($account);

            $this->emitCreatedPasswordResetTokenForAccount($account, $token, $resetNode);

            if ($this->sendResetPasswordMail) {
                $this->mailer->sendResetPasswordMail($email, $resetNode, $token);
            }
        }

        $this->redirectToNode(
            $redirectNode,
            [
                'resetEmail' => $email
            ]
        );

    }

    public function requestResetWithTokenAction(string $token, string $referrerNodeIdentifier, string $redirectNodeIdentifier, string $resetNodeIdentifier)
    {
        $passwordResetToken = $this->tokenService->getPasswortResetToken($token);

        if ($passwordResetToken !== null) {
            $arguments = [
                'email' => $passwordResetToken->getAccount()->getAccountIdentifier(),
                'redirectNodeIdentifier' => $redirectNodeIdentifier,
                'resetNodeIdentifier' => $resetNodeIdentifier
            ];

            $this->forward('requestReset', null, null, $arguments);
        }
        else {
            $redirectNode = $this->getTargetNode($referrerNodeIdentifier);

            $this->redirectToNode(
                $redirectNode,
                [
                    'token' => $token
                ]
            );
        }
    }

    /**
     * @param string $token
     * @param string $newPassword
     * @param string $passwordRepeat
     * @param string $nodeIdentifier Identifier of Node containing PasswordReset Plugin
     * @param string $redirectNodeIdentifier Identifier of node for redirect on success
     * @param bool $authenticate If set to true wired account will be authenticated after password was set successfully
     * @throws \Neos\Eel\Exception
     * @throws \Neos\Flow\Mvc\Exception\InvalidArgumentNameException
     * @throws \Neos\Flow\Mvc\Exception\InvalidArgumentTypeException
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     * @throws InvalidValidationOptionsException
     */
    public function resetAction(string $token, string $newPassword, string $passwordRepeat, string $nodeIdentifier, string $redirectNodeIdentifier, bool $authenticate = false): void
    {
        $matchedNode = $this->getTargetNode($nodeIdentifier);
        $matchedRedirectNode = $this->getTargetNode($redirectNodeIdentifier);
        $passwordResetToken = $this->tokenService->getPasswortResetToken($token);

        // TODO: validate token -> if it was used before it must be invalid
        if (!$this->tokenService->isValidTokenString($token)) {
            $this->emitResetTokenIsInvalid($passwordResetToken, $this->tokenService->getTokenValidationDate());
            $this->addFlashMessage(
                $this->translator->translateById('passwordManagement.reset.tokenInvalid.body', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset'),
                $this->translator->translateById('passwordManagement.reset.tokenInvalid.title', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset')
            );
            $this->redirectToNode(
                $matchedNode,
                [
                    'resetSuccess' => 'false',
                    'error' => 'invalidToken',
                ]
            );
        }

        // passwords do not match
        if ($newPassword !== $passwordRepeat) {
            $this->emitPasswordMismatchInResetAction($passwordResetToken, $newPassword, $passwordRepeat, $matchedNode, $matchedRedirectNode);
            $this->addFlashMessage(
                $this->translator->translateById('passwordManagement.reset.passwordNoMatch.body', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset'),
                $this->translator->translateById('passwordManagement.reset.passwordNoMatch.title', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset')
            );
            $this->redirectToNode(
                $matchedNode,
                [
                    'resetSuccess' => 'false',
                    'error' => 'passwordNoMatch',
                    'token' => $token
                ]
            );
        }

        // password pattern does not match
        $passwordResult = $this->getRegularExpressionValidatorResult($newPassword, $this->passwordPattern);
        if ($passwordResult->hasErrors()) {
            $this->emitPasswordPatternErrorInResetAction($passwordResetToken, $newPassword, $passwordResult, $matchedNode, $matchedRedirectNode);

            $defaultPasswordPatternDescription = $this->translator->translateById('passwordManagement.passwordPatternDescription', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset');
            $passwordPatternDescription = $this->getPasswordPatternDescription($matchedNode) ?? $defaultPasswordPatternDescription;

            $this->addFlashMessage(
                $this->translator->translateById('passwordManagement.passwordPatternError.body', [$passwordPatternDescription], null,null, 'Main', 'Networkteam.Neos.PasswordReset'),
                $this->translator->translateById('passwordManagement.passwordPatternError.title', [], null, null,'Main', 'Networkteam.Neos.PasswordReset')
            );
            $this->redirectToNode(
                $matchedNode,
                [
                    'resetSuccess' => 'false',
                    'error' => 'passwordPatternError',
                    'token' => $token
                ]
            );
        }

        $passwordResetToken->getAccount()->setCredentialsSource($this->hashService->hashPassword($newPassword, 'default'));

        // activate account if it is disabled
        if (!$passwordResetToken->getAccount()->isActive()) {
            $passwordResetToken->getAccount()->setExpirationDate(null);
        }

        $this->accountRepository->update($passwordResetToken->getAccount());
        $this->tokenService->removeToken($passwordResetToken);
        $this->persistenceManager->persistAll();

        try {
            if ($authenticate) {
                $this->authenticateAccount($passwordResetToken->getAccount()->getAccountIdentifier(), $newPassword);
                $this->emitAuthenticationAttemptHasBeenMade($passwordResetToken->getAccount(), $newPassword, $matchedNode, $matchedRedirectNode);
            }

            $this->redirectToNode(
                $matchedRedirectNode,
                [
                    'resetSuccess' => 'true'
                ]
            );
        } catch (AuthenticationRequiredException $exception) {
            $this->emitFailedToAuthenticateAccount($passwordResetToken->getAccount(), $newPassword, $matchedNode, $matchedRedirectNode);
            $this->addFlashMessage(
                $this->translator->translateById('passwordManagement.reset.loginFailed.body', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset'),
                $this->translator->translateById('passwordManagement.reset.loginFailed.title', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset')
            );

            $this->redirectToNode(
                $matchedNode,
                [
                    'loginSuccess' => 'false',
                    'error' => 'loginFailed',
                ]
            );
        }
    }

    /**
     * @param string $currentPassword
     * @param string $newPassword
     * @param string $passwordRepeat
     * @param string $nodeIdentifier
     * @throws InvalidValidationOptionsException
     * @throws \Neos\Eel\Exception
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     */
    public function changeAction(string $currentPassword, string $newPassword, string $passwordRepeat, string $nodeIdentifier): void
    {
        if ($this->securityContext->canBeInitialized()) {
            $account = $this->securityContext->getAccount();
        } else {
            return;
        }

        $matchedNode = $this->getTargetNode($nodeIdentifier);

        // invalid password
        if (!$this->hashService->validatePassword($currentPassword, $account->getCredentialsSource())) {
            $this->emitCurrentPasswordIsInvalid($account, $currentPassword, $matchedNode);
            $this->addFlashMessage(
                $this->translator->translateById('passwordManagement.change.currentPasswordInvalid.body', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset'),
                $this->translator->translateById('passwordManagement.change.currentPasswordInvalid.title', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset')
            );

            $this->redirectToNode(
                $matchedNode,
                [
                    'changeSuccess' => 'false',
                    'error' => 'currentPasswordInvalid',
                ]
            );
        }

        // passwords do not match
        if ($newPassword !== $passwordRepeat) {
            $this->emitPasswordMismatchInChangeAction($account, $newPassword, $passwordRepeat, $matchedNode);
            $this->addFlashMessage(
                $this->translator->translateById('passwordManagement.change.passwordNoMatch.body', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset'),
                $this->translator->translateById('passwordManagement.change.passwordNoMatch.title', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset')
            );

            $this->redirectToNode(
                $matchedNode,
                [
                    'changeSuccess' => 'false',
                    'error' => 'passwordNoMatch',
                ]
            );
        }

        // password pattern does not match
        $passwordResult = $this->getRegularExpressionValidatorResult($newPassword, $this->passwordPattern);
        if ($passwordResult->hasErrors()) {
            $this->emitPasswordPatternErrorInChangeAction($newPassword, $passwordResult, $matchedNode);

            $defaultPasswordPatternDescription = $this->translator->translateById('passwordManagement.passwordPatternDescription', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset');
            $passwordPatternDescription = $this->getPasswordPatternDescription($matchedNode) ?? $defaultPasswordPatternDescription;

            $this->addFlashMessage(
                $this->translator->translateById('passwordManagement.passwordPatternError.body', [$passwordPatternDescription], null,null, 'Main', 'Networkteam.Neos.PasswordReset'),
                $this->translator->translateById('passwordManagement.passwordPatternError.title', [], null, null,'Main', 'Networkteam.Neos.PasswordReset')
            );

            $this->redirectToNode(
                $matchedNode,
                [
                    'changeSuccess' => 'false',
                    'error' => 'passwordPatternError',
                ]
            );
        }

        // change password only if it differs from current password
        if ($currentPassword !== $newPassword) {
            $account->setCredentialsSource($this->hashService->hashPassword($newPassword, 'default'));
            $this->accountRepository->update($account);
            $this->persistenceManager->persistAll();
            $this->emitPasswordHasBeenChanged($account, $newPassword, $matchedNode);
        }

        $this->addFlashMessage(
            $this->translator->translateById('passwordManagement.change.success.body', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset'),
            $this->translator->translateById('passwordManagement.change.success.title', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset')
        );

        $this->redirectToNode(
            $matchedNode,
            [
                'changeSuccess' => 'true'
            ]
        );
    }

    /**
     * @param string $nodeIdentifier
     * @return NodeInterface|null
     * @throws \Neos\Eel\Exception
     */
    protected function getTargetNode(string $nodeIdentifier): ?NodeInterface
    {
        $contentContext = $this->contentContextFactory->create([
            'workspaceName' => 'live',
            'invisibleContentShown' => false,
            'inaccessibleContentShown' => false
        ]);

        $flowQuery = new \Neos\Eel\FlowQuery\FlowQuery([$contentContext->getRootNode()]);
        $matchedNode = $flowQuery
            ->find(sprintf('#%s', $nodeIdentifier))
            ->closest('[instanceof Neos.Neos:Document]')
            ->get(0);
        return $matchedNode;
    }

    /**
     * @param string $accountIdentifier
     * @param NodeInterface $resetDocumentNode
     * @FLow\Signal
     */
    protected function emitAccountForRequestedResetIsNotFound(string $accountIdentifier, NodeInterface $resetDocumentNode): void
    {
    }

    /**
     * @param Account $account
     * @param ActionRequest $request
     * @param ActionResponse $response
     * @param NodeInterface $resetDocumentNode
     * @FLow\Signal
     */
    protected function emitAccountForRequestedResetIsInactive(
        Account $account,
        ActionRequest $request,
        ActionResponse $response,
        NodeInterface $resetDocumentNode
    ): void
    {
    }

    /**
     * @param PasswordResetToken|null $token
     * @param \DateTime $validationDate
     * @FLow\Signal
     */
    protected function emitResetTokenIsInvalid(?PasswordResetToken $token, \DateTime $validationDate): void
    {
    }

    /**
     * @param Account $account
     * @param PasswordResetToken $token
     * @param NodeInterface $resetDocumentNode
     * @FLow\Signal
     */
    protected function emitCreatedPasswordResetTokenForAccount(Account $account, PasswordResetToken $token, NodeInterface $resetDocumentNode): void
    {
    }

    /**
     * @param PasswordResetToken $token
     * @param string $newPassword
     * @param string $passwordRepeat
     * @param NodeInterface|null $matchedNode
     * @param NodeInterface|null $matchedRedirectNode
     */
    protected function emitPasswordMismatchInResetAction(
        PasswordResetToken $token,
        string $newPassword,
        string $passwordRepeat,
        ?NodeInterface $matchedNode,
        ?NodeInterface $matchedRedirectNode
    ): void
    {
    }

    /**
     * @param PasswordResetToken $token
     * @param string $newPassword
     * @param Result $errorResult
     * @param NodeInterface|null $matchedNode
     * @param NodeInterface|null $matchedRedirectNode
     */
    protected function emitPasswordPatternErrorInResetAction(
        PasswordResetToken $token,
        string $newPassword,
        Result $errorResult,
        ?NodeInterface $matchedNode,
        ?NodeInterface $matchedRedirectNode
    ): void
    {
    }

    /**
     * @param Account $getAccount
     * @param string $newPassword
     * @param NodeInterface|null $matchedNode
     * @param NodeInterface|null $matchedRedirectNode
     */
    protected function emitAuthenticationAttemptHasBeenMade(
        Account $getAccount,
        string $newPassword,
        ?NodeInterface $matchedNode,
        ?NodeInterface $matchedRedirectNode
    ): void
    {
    }

    /**
     * @param Account $getAccount
     * @param string $newPassword
     * @param NodeInterface|null $matchedNode
     * @param NodeInterface|null $matchedRedirectNode
     */
    protected function emitFailedToAuthenticateAccount(
        Account $getAccount,
        string $newPassword,
        ?NodeInterface $matchedNode,
        ?NodeInterface $matchedRedirectNode
    ): void
    {
    }

    /**
     * @param Account $account
     * @param string $currentPassword
     * @param NodeInterface|null $matchedNode
     */
    protected function emitCurrentPasswordIsInvalid(
        Account $account,
        string $currentPassword,
        ?NodeInterface $matchedNode
    ): void
    {
    }

    protected function emitPasswordHasBeenChanged(
        Account $account,
        string $newPassword,
        ?NodeInterface $matchedNode
    ): void
    {
    }

    protected function emitPasswordMismatchInChangeAction(
        Account $account,
        string $newPassword,
        string $passwordRepeat,
        ?NodeInterface $matchedNode
    ): void
    {
    }

    protected function emitPasswordPatternErrorInChangeAction(
        string $newPassword,
        Result $errorResult,
        ?NodeInterface $matchedNode
    ): void
    {
    }

    /**
     * @param string $accountIdentifier
     * @param string $password
     * @throws AuthenticationRequiredException
     * @throws \Neos\Flow\Mvc\Exception\InvalidArgumentNameException
     * @throws \Neos\Flow\Mvc\Exception\InvalidArgumentTypeException
     * @throws \Neos\Flow\Security\Exception\NoTokensAuthenticatedException
     */
    protected function authenticateAccount(string $accountIdentifier, string $password): void
    {
        $tokens = $this->authenticationManager->getSecurityContext()->getAuthenticationTokens();
        $authenticationToken = null;

        // take authenticationToken from first available configured authenticationProvider
        foreach ($this->settings['authenticationProviders'] as $authenticationProviderName) {
            if ($tokens[$authenticationProviderName]) {
                $authenticationToken = $tokens[$authenticationProviderName] ?? null;
                break;
            }
        }

        if (!$authenticationToken instanceof UsernamePassword) {
            throw new \Exception('Configured token object is not of required type', 1581345740);
        }

        // set username and password on request for updating authenticationToken
        $this->request->setArgument(
            '__authentication',
            [
                'Neos' => [
                    'Flow' => [
                        'Security' => [
                            'Authentication' => [
                                'Token' => [
                                    'UsernamePassword' => [
                                        'username' => $accountIdentifier,
                                        'password' => $password
                                    ]
                                ]
                            ]
                        ]
                    ]
                ]
            ]
        );

        $authenticationToken->updateCredentials($this->request);

        $this->authenticationManager->authenticate();
    }

    protected function redirectToNode(?NodeInterface $node, $arguments = []): void
    {
        $redirectTarget = $this->linkService->createNodeUri(
            $this->getControllerContext(),
            $node,
            null,
            'html',
            false,
            $arguments
        );

        $this->redirectToUri($redirectTarget);
    }

    /**
     * @param string $value
     * @param string $pattern Regular expression pattern without starting and ending delimiters
     * @return Result
     * @throws InvalidValidationOptionsException
     */
    protected function getRegularExpressionValidatorResult(string $value, string $pattern): Result
    {
        $validator = new RegularExpressionValidator([
            // we must add starting and ending delimiters so the passwordPattern does work with html input pattern attribute
            'regularExpression' => sprintf("/%s/", $pattern)
        ]);

        return $validator->validate($value);
    }

    protected function getPasswordPatternDescription(NodeInterface $node): ?string
    {
        try {
            $passwordPatternDescription = trim($node->getProperty('passwordPatternDescription'));
            if (empty($passwordPatternDescription)) {
                $passwordPatternDescription = null;
            }
        } catch(\Exception $e) {
            $passwordPatternDescription = null;
        }

        return $passwordPatternDescription;
    }

}
