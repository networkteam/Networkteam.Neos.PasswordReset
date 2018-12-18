<?php
namespace Networkteam\Neos\PasswordReset\Controller;

/***************************************************************
 *  (c) 2018 networkteam GmbH - all rights reserved
 ***************************************************************/

use Neos\ContentRepository\Domain\Model\NodeInterface;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Controller\ActionController;
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
     * @param string $email
     * @param string $nodeIdentifier
     * @throws \Neos\Eel\Exception
     * @throws \Neos\Flow\Mvc\Exception\StopActionException
     * @throws \Neos\Flow\Mvc\Exception\UnsupportedRequestTypeException
     * @throws \Neos\Flow\Persistence\Exception\IllegalObjectTypeException
     * @throws \Neos\Neos\Exception
     * @Flow\SkipCsrfProtection
     */
    public function requestResetAction(string $email, string $nodeIdentifier)
    {
        $account = null;
        foreach($this->settings['authenticationProviders'] as $authenticationProviderName) {
            $account = $this->accountRepository->findActiveByAccountIdentifierAndAuthenticationProviderName($email, $authenticationProviderName);
            if ($account !== null) {
                break;
            }
        }
        $matchedNode = $this->getRedirectTarget($nodeIdentifier);

        if ($account === null) {
            $this->mailer->sendNoAccountMail($email, $matchedNode);
        } else {
            $token = new PasswordResetToken($account);
            $this->passwordResetTokenRepository->add($token);
            $this->persistenceManager->persistAll();
            $this->mailer->sendResetPasswordMail($email, $matchedNode, $token);
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


    public function resetAction(string $token, string $newPassword, string $passwordRepeat, string $nodeIdentifier)
    {
        $matchedNode = $this->getRedirectTarget($nodeIdentifier);
        $validaDate = new \DateTime('now - 24 hours');

        $token = $this->passwordResetTokenRepository->findOneByToken($token);

        if ($token === null || $token->getCreatedAt() <= $validaDate) {
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

    /**
     * @param string $nodeIdentifier
     * @return mixed
     * @throws \Neos\Eel\Exception
     */
    private function getRedirectTarget(string $nodeIdentifier)
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
}
