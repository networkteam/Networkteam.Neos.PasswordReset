Password Reset
==============

Allow users to reset their password withing the frontend.

Installation
------------

```
$ composer require networkteam/neos-passwordreset
$ ./flow doctrine:migrate
```

Configuration
-------------
Overwrite the template paths to point to your own Templates. These can be copies from the original ones. They are lend 
by the great project from [postmarkapp.com](https://postmarkapp.com/transactional-email-templates).

```
Networkteam:
  Neos:
    PasswordReset:
      authenticationProviders:
        - Networkteam.Neos.FrontendLogin:Frontend
      senderAddress: 'no-reply@organisation.org'
      templatePaths:
        noAccountMailHtml: 'resource://Networkteam.Neos.PasswordReset/Private/Templates/Mail/password-reset-help.html'
        noAccountMailTxt: 'resource://Networkteam.Neos.PasswordReset/Private/Templates/Mail/password-reset-help.txt'
        resetPasswordMailHtml: 'resource://Networkteam.Neos.PasswordReset/Private/Templates/Mail/password-reset-link.html'
        resetPasswordMailTxt: 'resource://Networkteam.Neos.PasswordReset/Private/Templates/Mail/password-reset-link.txt'
```
The configuration `authenticationProviders` is an array of providers a reset is possible for. When multiple providers are
given the email address is tested for each provider and the first one an account is found for creates the mail.


### Policy

To make the password change functionality work, you have to add the PasswordChange privilege (`Networkteam.Neos.PasswordReset:PasswordChange`) 
to the member area role. If you use the [networkteam FrontendLogin package](https://github.com/networkteam/Networkteam.Neos.FrontendLogin) 
it looks as follows:

**Policy.yaml**

```
roles:
  'Networkteam.Neos.FrontendLogin:MemberArea':
    abstract: true
    privileges:
      - privilegeTarget: 'Networkteam.Neos.PasswordReset:PasswordChange'
        permission: GRANT
```

### Signals

This package provides [signals](https://flowframework.readthedocs.io/en/stable/TheDefinitiveGuide/PartIII/SignalsAndSlots.html?highlight=signal#signals-and-slots) 
for certain events.

**requestResetAction**

| Signal name | Description | Parameters |
| ----------- | ------------| ---------- |
| **requestedAccountForResetIsNotFound** | is fired during requestResetAction when no account could be found for the given email address | `email`, `authenticationProviderName` |
| **requestedAccountForResetIsInactive** | is fired during requestResetAction when the found account is inactive | `account`, `request`, `response` |
| **createdPasswordResetTokenForAccount** | is fired during requestResetActionwhen the password reset token has been created | `account`, `token` |
| **resetTokenIsInvalid** | is fired during resetAction when given token is invalid | `token`, `validationDate` |

Information flow
----------------
If the user requests a new Password an email ist sent to the given address. If no associated account could be found for 
the email address an email with this information is sent to inform the user that he probably used another email address 
for this account.

If an account was found, a token is generated to identify the request and an email is send to the user. The token is 
validated when the user clicks on the link in the email and submits the subsequently shown form with the new password.

Requirements / Short comings
----------------------------

The accounts need to have an email address as identifier aka. username. This is needed due to the nature of the underlying
handling of electronic addresses in Neos. There should also be no accounts with the same email address and different 
authentication providers. This is possible but only for the first configured authentication provider a reset is possible.


Styling
-------

To bring the forms in good shape for you application / website overwrite the fusion templates. There is one for each 
form / response. 

- RequestForm is the form initially shown to enter an email address
- RequestAccepted is shown after an email was sent
- ResetForm is the form shown to give the new password
- ResetSucceeded is the fusion executed when the password reset is complete

As variables for the templates are available:

```yaml
- node # the node the form was sent from
- email # the email provided in the form
- operating_system # a string from the referer
- browser_name # a string from the referer

```
