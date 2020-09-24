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

    public function isValid(string $token): bool
    {
        return $this->tokenService->isValidTokenString($token);
    }

    public function isToken(string $token): bool
    {
        return $this->tokenService->isToken($token);
    }

    public function allowsCallOfMethod($methodName)
    {
        return true;
    }
}