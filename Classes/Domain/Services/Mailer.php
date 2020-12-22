<?php
namespace Networkteam\Neos\PasswordReset\Domain\Services;

/***************************************************************
 *  (c) 2018 networkteam GmbH - all rights reserved
 ***************************************************************/

use Neos\ContentRepository\Domain\Model\NodeInterface;
use Networkteam\Neos\PasswordReset\Domain\Model\PasswordResetToken;
use Neos\Flow\Annotations as Flow;

class Mailer
{

    /**
     * @Flow\InjectConfiguration("templatePaths")
     * @var array
     */
    protected $templatePaths;

    /**
     * @Flow\InjectConfiguration("senderAddress")
     * @var string
     */
    protected $senderAddress;

    /**
     * @Flow\InjectConfiguration("tokenLifetime")
     * @var string
     */
    protected $tokenLifetime;

    /**
     * @var \Neos\Flow\I18n\Translator
     * @Flow\Inject
     */
    protected $translator;

    /**
     * @var \Neos\Party\Domain\Repository\PartyRepository
     * @Flow\Inject
     */
    protected $partyRepository;

    public function sendNoAccountMail(string $email, NodeInterface $passwordResetPage)
    {
        $translateId = 'mail.noAccountSubject';
        $subject = $this->translateById($translateId);
        $message = new \Neos\SwiftMailer\Message($subject);

        $uaInfo = parse_user_agent();

        $viewVariables = [
            'email' => $email,
            'node' => $passwordResetPage,
            'operating_system' => $uaInfo['platform'],
            'browser_name' => $uaInfo['browser']
        ];

        $htmlBody = $this->renderTemplate($this->templatePaths['noAccountMailHtml'], $viewVariables);
        $txtBody = $this->renderTemplate($this->templatePaths['noAccountMailTxt'], $viewVariables);

        $message->setBody($txtBody);
        $message->addPart($htmlBody, 'text/html');
        $message->setTo($email);
        $message->setFrom($this->senderAddress);
        $message->send();
    }


    public function sendResetPasswordMail(string $email, NodeInterface $passwordResetPage, PasswordResetToken $token)
    {
        $translateId = 'mail.noAccountSubject';
        $subject = $this->translateById($translateId);
        $message = new \Neos\SwiftMailer\Message($subject);

        $uaInfo = parse_user_agent();

        $viewVariables = [
            'token' => $token,
            'token_lifetime' => $this->tokenLifetime,
            'email' => $email,
            'node' => $passwordResetPage,
            'operating_system' => $uaInfo['platform'],
            'browser_name' => $uaInfo['browser'],
            'user' => $this->partyRepository->findOneHavingAccount($token->getAccount())
        ];

        $htmlBody = $this->renderTemplate($this->templatePaths['resetPasswordMailHtml'], $viewVariables);
        $txtBody = $this->renderTemplate($this->templatePaths['resetPasswordMailTxt'], $viewVariables);

        $message->setBody($txtBody);
        $message->addPart($htmlBody, 'text/html');
        $message->setTo($email);
        $message->setFrom($this->senderAddress);
        $message->send();
    }

    /**
     * @param $translateId
     * @return string
     */
    private function translateById($translateId): string
    {
        $subject = $this->translator->translateById($translateId, [], null, null, 'Main', 'Networkteam.Neos.PasswordReset');
        return $subject;
    }

    /**
     * @param $templatePath
     * @param $viewVariables
     * @return string
     * @throws \Neos\FluidAdaptor\Exception
     */
    private function renderTemplate($templatePath, $viewVariables): string
    {
        $view = new \Neos\FluidAdaptor\View\StandaloneView();
        $view->setTemplatePathAndFilename($templatePath);
        $view->assignMultiple($viewVariables);
        $htmlBody = $view->render();
        return $htmlBody;
    }
}