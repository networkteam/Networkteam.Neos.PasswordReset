<?php
namespace Networkteam\Neos\PasswordReset\Domain\Model;

/***************************************************************
 *  (c) 2018 networkteam GmbH - all rights reserved
 ***************************************************************/

use Neos\Flow\Annotations as Flow;
use Doctrine\ORM\Mapping as ORM;

/**
 * @Flow\Entity
 * @ORM\Table(name="passwordresettoken")
 */
class PasswordResetToken
{

    const TOKEN_LENGTH = 32;
    /**
     * @var \DateTime
     */
    protected $createdAt;

    /**
     * @var string
     */
    protected $token;

    /**
     * @var \Neos\Flow\Security\Account
     * @ORM\ManyToOne
     */
    protected $account;

    /**
     * PasswordResetToken constructor.
     * @param \DateTime $createdAt
     * @param string $token
     * @param \Neos\Flow\Security\Account $account
     */
    public function __construct(\Neos\Flow\Security\Account $account, \DateTime $createdAt = null, string $token = null)
    {
        $this->createdAt = $createdAt === null ? new \DateTime() : $createdAt;
        $this->token = $token === null ? \Neos\Flow\Utility\Algorithms::generateRandomToken(self::TOKEN_LENGTH) : $token;
        $this->account = $account;
    }

    /**
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * @return \Neos\Flow\Security\Account
     */
    public function getAccount(): \Neos\Flow\Security\Account
    {
        return $this->account;
    }

    /**
     * @return \DateTime
     */
    public function getCreatedAt(): \DateTime
    {
        return $this->createdAt;
    }
}