<?php
namespace Networkteam\Neos\PasswordReset\Helper;

use Neos\Flow\Mvc\ActionRequest;

/***************************************************************
 *  (c) 2021 networkteam GmbH - all rights reserved
 ***************************************************************/

class FlashMessageHelperFactory
{

    public static function create(ActionRequest $request): FlashMessageHelper
    {
        return new FlashMessageHelper($request);
    }
}