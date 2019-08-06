<?php
namespace Networkteam\Neos\PasswordReset\Service;

/***************************************************************
 *  (c) 2019 networkteam GmbH - all rights reserved
 ***************************************************************/

use Neos\ContentRepository\Domain\Model\NodeInterface;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Security\Account;
use Neos\Neos\Service\LinkingService;
use Networkteam\Neos\PasswordReset\Domain\Model\PasswordResetToken;
use Networkteam\Neos\PasswordReset\Domain\Repository\PasswordResetTokenRepository;

/**
 * @Flow\Scope("singleton")
 */
class TokenService
{

    /**
     * @var PasswordResetTokenRepository
     * @Flow\Inject
     */
    protected $passwordResetTokenRepository;

    /**
     * @Flow\Inject
     * @var PersistenceManagerInterface
     */
    protected $persistenceManager;

    public function createPasswordResetTokenForAccount(Account $account): PasswordResetToken
    {
        $token = new PasswordResetToken($account);
        $this->passwordResetTokenRepository->add($token);
        $this->persistenceManager->persistAll();

        return $token;
    }
}