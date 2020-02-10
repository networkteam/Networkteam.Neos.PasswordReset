<?php
namespace Networkteam\Neos\PasswordReset\Controller;

/***************************************************************
 *  (c) 2018 networkteam GmbH - all rights reserved
 ***************************************************************/

use Neos\ContentRepository\Domain\Model\NodeInterface;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Http\Response;
use Neos\Flow\Mvc\Controller\ActionController;
use Neos\Flow\Mvc\RequestInterface;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\Authentication\AuthenticationManagerInterface;
use Neos\Flow\Security\Authentication\Token\UsernamePassword;
use Neos\Flow\Security\Context as SecurityContext;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Networkteam\Neos\PasswordReset\Domain\Model\PasswordResetToken;
use Networkteam\Neos\PasswordReset\Domain\Repository\PasswordResetTokenRepository;

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
     * @var PasswordResetTokenRepository
     * @Flow\Inject
     */
    protected $passwordResetTokenRepository;

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
     * @var AuthenticationManagerInterface
     * @Flow\Inject
     */
    protected $authenticationManager;

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
        $account = null;
        foreach($this->settings['authenticationProviders'] as $authenticationProviderName) {
            $account = $this->accountRepository->findByAccountIdentifierAndAuthenticationProviderName($email, $authenticationProviderName);
            if ($account !== null) {
                break;
            }
        }

        $redirectNode = $this->getTargetNode($redirectNodeIdentifier);
        $resetNode = $this->getTargetNode($resetNodeIdentifier);

        if ($account === null) {
            $this->emitAccountForRequestedResetIsNotFound($email);

            if ($this->sendNoAccountMail) {
                $this->mailer->sendNoAccountMail($email, $resetNode);
            }
        } elseif (!$account->isActive()) {
            $this->emitAccountForRequestedResetIsInactive($account, $this->request, $this->response);
        } else {
            $token = $this->tokenService->createPasswordResetTokenForAccount($account);

            $this->emitCreatedPasswordResetTokenForAccount($account, $token);

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
     */
    public function resetAction(string $token, string $newPassword, string $passwordRepeat, string $nodeIdentifier, string $redirectNodeIdentifier, bool $authenticate = false): void
    {
        $matchedNode = $this->getTargetNode($nodeIdentifier);
        $matchedRedirectNode = $this->getTargetNode($redirectNodeIdentifier);
        $validationDate = new \DateTime('now - 24 hours');

        /** @var PasswordResetToken $token */
        $token = $this->passwordResetTokenRepository->findOneByToken($token);

        // TODO: validate token -> if it was used before it must be invalid
        if ($token === null || $token->getCreatedAt() <= $validationDate) {
            $this->emitResetTokenIsInvalid($token, $validationDate);
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

        if ($newPassword !== $passwordRepeat) {
            $this->addFlashMessage(
                $this->translator->translateById('passwordManagement.reset.passwordMissmatch.body', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset'),
                $this->translator->translateById('passwordManagement.reset.passwordMissmatch.title', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset')
            );
            $this->redirectToNode(
                $matchedNode,
                [
                    'resetSuccess' => 'false',
                    'error' => 'passwordNoMatch',
                ]
            );
        }

        $token->getAccount()->setCredentialsSource($this->hashService->hashPassword($newPassword, 'default'));

        // activate account if it is disabled
        if (!$token->getAccount()->isActive()) {
            $token->getAccount()->setExpirationDate(null);
        }

        $this->accountRepository->update($token->getAccount());
        $this->passwordResetTokenRepository->remove($token);
        $this->persistenceManager->persistAll();

        try {
            if ($authenticate) {
                $this->authenticateAccount($token, $newPassword);
            }

            $this->redirectToNode(
                $matchedRedirectNode,
                [
                    'resetSuccess' => 'true'
                ]
            );
        } catch (AuthenticationRequiredException $exception) {
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

        // change password only if it differs from current password
        if ($currentPassword !== $newPassword) {
            $account->setCredentialsSource($this->hashService->hashPassword($newPassword, 'default'));
            $this->accountRepository->update($account);
            $this->persistenceManager->persistAll();
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
     * @FLow\Signal
     */
    protected function emitAccountForRequestedResetIsNotFound(string $accountIdentifier): void
    {
    }

    /**
     * @param Account $account
     * @param RequestInterface $request
     * @param Response $response
     * @FLow\Signal
     */
    protected function emitAccountForRequestedResetIsInactive(Account $account, RequestInterface $request, Response $response): void
    {
    }

    /**
     * @param PasswordResetToken|null $token
     * @param \DateTime $validationDate
     * @FLow\Signal
     */
    private function emitResetTokenIsInvalid(?PasswordResetToken $token, \DateTime $validationDate): void
    {
    }

    /**
     * @param Account $account
     * @param PasswordResetToken $token
     * @FLow\Signal
     */
    protected function emitCreatedPasswordResetTokenForAccount(Account $account, PasswordResetToken $token): void
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
}
