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
use Neos\Flow\Security\Context as SecurityContext;
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
     * @param string $email
     * @param string $nodeIdentifier
     * @throws \Neos\Eel\Exception
     * @throws \Neos\Flow\Mvc\Exception\StopActionException
     * @throws \Neos\Flow\Mvc\Exception\UnsupportedRequestTypeException
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     * @throws \Neos\Neos\Exception
     * @Flow\SkipCsrfProtection
     */
    public function requestResetAction(string $email, string $nodeIdentifier): void
    {
        $account = null;
        foreach($this->settings['authenticationProviders'] as $authenticationProviderName) {
            $account = $this->accountRepository->findByAccountIdentifierAndAuthenticationProviderName($email, $authenticationProviderName);
            if ($account !== null) {
                break;
            }
        }

        $matchedNode = $this->getRedirectTarget($nodeIdentifier);

        if ($account === null) {
            $this->emitAccountForRequestedResetIsNotFound($email);

            if ($this->sendNoAccountMail) {
                $this->mailer->sendNoAccountMail($email, $matchedNode);
            }
        } elseif (!$account->isActive()) {
            $this->emitAccountForRequestedResetIsInactive($account, $this->request, $this->response);
        } else {
            $token = $this->tokenService->createPasswordResetTokenForAccount($account);

            $this->emitCreatedPasswordResetTokenForAccount($account, $token);

            if ($this->sendResetPasswordMail) {
                $this->mailer->sendResetPasswordMail($email, $matchedNode, $token);
            }
        }

        $redirectTarget = $this->linkService->createNodeUri(
            $this->getControllerContext(),
            $matchedNode,
            null,
            'html',
            false,
            [
                'resetEmail' => $email
            ]
        );

        $this->redirectToUri($redirectTarget);

    }


    public function resetAction(string $token, string $newPassword, string $passwordRepeat, string $nodeIdentifier): void
    {
        $matchedNode = $this->getRedirectTarget($nodeIdentifier);
        $validationDate = new \DateTime('now - 24 hours');

        /** @var PasswordResetToken $token */
        $token = $this->passwordResetTokenRepository->findOneByToken($token);

        if ($token === null || $token->getCreatedAt() <= $validationDate) {
            $this->emitResetTokenIsInvalid($token, $validationDate);

            $redirectTarget = $this->linkService->createNodeUri(
                $this->getControllerContext(),
                $matchedNode,
                null,
                'html',
                false,
                [
                    'resetSuccess' => 'false',
                    'error' => 'invalidToken',
                ]
            );

            $this->redirectToUri($redirectTarget);
        }

        if ($newPassword !== $passwordRepeat) {
            $redirectTarget = $this->linkService->createNodeUri(
                $this->getControllerContext(),
                $matchedNode,
                null,
                'html',
                false,
                [
                    'resetSuccess' => 'false',
                    'error' => 'passwordNoMatch',
                ]
            );

            $this->redirectToUri($redirectTarget);
        }

        $token->getAccount()->setCredentialsSource($this->hashService->hashPassword($newPassword, 'default'));

        // activate account if it is disabled
        if (!$token->getAccount()->isActive()) {
            $token->getAccount()->setExpirationDate(null);
        }

        $this->accountRepository->update($token->getAccount());
        $this->persistenceManager->persistAll();


        $redirectTarget = $this->linkService->createNodeUri(
            $this->getControllerContext(),
            $matchedNode,
            null,
            'html',
            false,
            [
                'resetSuccess' => 'true'
            ]
        );

        $this->redirectToUri($redirectTarget);
    }

    public function changeAction(string $currentPassword, string $newPassword, string $passwordRepeat, string $nodeIdentifier): void
    {
        if ($this->securityContext->canBeInitialized()) {
            $account = $this->securityContext->getAccount();
        } else {
            return;
        }

        $matchedNode = $this->getRedirectTarget($nodeIdentifier);

        if (!$this->hashService->validatePassword($currentPassword, $account->getCredentialsSource())) {
            $redirectTarget = $this->linkService->createNodeUri(
                $this->getControllerContext(),
                $matchedNode,
                null,
                'html',
                false,
                [
                    'changeSuccess' => 'false',
                    'error' => 'currentPasswordInvalid',
                ]
            );

            $this->addFlashMessage(
                $this->translator->translateById('passwordManagement.change.currentPasswordInvalid.body', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset'),
                $this->translator->translateById('passwordManagement.change.currentPasswordInvalid.title', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset')
            );

            $this->redirectToUri($redirectTarget);
        }

        if ($newPassword !== $passwordRepeat) {
            $redirectTarget = $this->linkService->createNodeUri(
                $this->getControllerContext(),
                $matchedNode,
                null,
                'html',
                false,
                [
                    'changeSuccess' => 'false',
                    'error' => 'passwordNoMatch',
                ]
            );

            $this->addFlashMessage(
                $this->translator->translateById('passwordManagement.change.passwordNoMatch.body', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset'),
                $this->translator->translateById('passwordManagement.change.passwordNoMatch.title', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset')
            );

            $this->redirectToUri($redirectTarget);
        }

        // only change password if it differs from current password
        if ($currentPassword !== $newPassword) {
            $account->setCredentialsSource($this->hashService->hashPassword($newPassword, 'default'));
            $this->accountRepository->update($account);
            $this->persistenceManager->persistAll();
        }

        $redirectTarget = $this->linkService->createNodeUri(
            $this->getControllerContext(),
            $matchedNode,
            null,
            'html',
            false,
            [
                'changeSuccess' => 'true'
            ]
        );

        $this->addFlashMessage(
            $this->translator->translateById('passwordManagement.change.success.body', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset'),
            $this->translator->translateById('passwordManagement.change.success.title', [], null, null, 'Main', 'Networkteam.Neos.PasswordReset')
        );

        $this->redirectToUri($redirectTarget);
    }

    /**
     * @param string $nodeIdentifier
     * @return NodeInterface|null
     * @throws \Neos\Eel\Exception
     */
    protected function getRedirectTarget(string $nodeIdentifier): ?NodeInterface
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
}
