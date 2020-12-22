<?php
namespace Networkteam\Neos\PasswordReset\EelHelper;

/***************************************************************
 *  (c) 2020 networkteam GmbH - all rights reserved
 ***************************************************************/

use Neos\Eel\ProtectedContextAwareInterface;
use Neos\Flow\Annotations as Flow;

class TokenHelper implements ProtectedContextAwareInterface
{

    /**
     * @Flow\Inject
     * @var \Networkteam\Neos\PasswordReset\Service\TokenService
     */
    protected $tokenService;

    /**
     * @param string $token
     * @return bool
     */
    public function isValid($token): bool
    {
        $token = (string)$token;

        return $this->tokenService->isValidTokenString($token);
    }

    /**
     * @param string $token
     * @return bool
     */
    public function isToken($token): bool
    {
        $token = (string)$token;

        return $this->tokenService->isToken($token);
    }

    public function allowsCallOfMethod($methodName)
    {
        return true;
    }
}