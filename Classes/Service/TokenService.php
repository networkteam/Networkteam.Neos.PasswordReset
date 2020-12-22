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
     * @var string
     * @Flow\InjectConfiguration("tokenLifetime")
     */
    protected $tokenLifetime;

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

    public function isValidTokenString(string $token): bool
    {
        $passwordResetToken = $this->getPasswortResetToken($token);
        return $passwordResetToken !== null && $this->isValid($passwordResetToken);
    }

    public function isValid(PasswordResetToken $token): bool
    {
        return $token->getCreatedAt() >= $this->getTokenValidationDate();
    }

    public function isToken(string $token): bool
    {
        return $this->getPasswortResetToken($token) !== null;
    }

    /**
     * Returns general token expiration date.
     *
     * @return \DateTime
     */
    public function getTokenValidationDate(): \DateTime
    {
        try {
            $tokenValidationDate = new \DateTime(
                sprintf('now - %s', trim($this->tokenLifetime))
            );
        } catch (\Exception $e) {
            $tokenValidationDate = new \DateTime('now - 24 hours');
        }

        return $tokenValidationDate;
    }

    public function getPasswortResetToken(string $token): ?PasswordResetToken
    {
        return $this->passwordResetTokenRepository->findOneByToken($token);
    }

    public function removeToken(PasswordResetToken $token): void
    {
        $this->passwordResetTokenRepository->remove($token);
    }
}