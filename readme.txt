=== More Secure Login ===
Contributors: juliobox
Donate link: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=KJGT942XKWJ6W
Tags: secure, security, login, password
Requires at least: 2.8
Tested up to: 3.3.2
Stable tag: trunk

This is a strong authentication plugin. You have to fill a second field, kind of password but this one comes from a printed card you own (FR/EN).

== Description ==
- PLEASE CHECK YOUR EMAIL SETTINGS IN YOUR PROFILE BEFORE LOGOUT THE FIRST TIME AND WAIT FOR THE MAIL CONTAINING THE SECURE CARD. THANK YOU -

* A new field is added below the password one.
* It requires a new code, this code is on a "MSL Secure Card" (png or html table).
* This card contains 64 codes, each code contains 4 chars. You have to print it!
* Now when someone wants to log on any account, even if he knows the password, he can not use it without the code.

This kind of authentication is called **"Strong Authentication"**, strong authentication is associated with at least two-factor authentication.
Your usual password is the first and only factor, this plugin adds an external factor : a MSL Secure Card.
Now, you have 2 secure factors to log in.

When someone wants to log in any account, he has to fill the username, password and now a **"MSL Code"** field.
This code is printed on a card (you have to print it) and contains a code from A1 to H8.
Without this code, he can not log in!

The codes are not stored in your DB, all codes are hashed like your password is. So, the codes are as secure as your password is.

Every blog which needs to improve its login's security needs this plugin.

== Installation ==

1. Upload the *"baw-more-secure-login"* to the *"/wp-content/plugins/"* directory
1. Activate the plugin through the *"Plugins"* menu in WordPress
1. You'll receive by email your MSL Secure Card.
1. All users have to ask for a password reset to get their own MSL Secure Card
1. You *(the person whom activating the plugin or any other admin)* can renew any user's card with users bulk actions.



== Frequently Asked Questions ==

= Why this is more secure ? =

This kind of authencation is called **"Strong Authentication"**, strong authentication is associated with at least two-factor authentication.
Your usual password is the first and only factor, this plugin adds an external factor : a MSL Secure Card.
Now, you have 2 secure factors to log in.

= How does this works? =

When someone wants to log in any account, he has to fill the username, password and now a **"MSL Code"** field.
This code is printed on a card (you have to print it) and contains a code from A1 to H8.
Without this code, he can not log in!

= Who needs it? =

Every blog which needs to improve its login's security.

= Need more help? =

Read http://baw.li/mslhelp/help-en.html (fr: http://baw.li/mslhelp/help-fr.html) to get more functionnality details.

= Dev question: What are the hooks? =

See "http://baw.li/mslhelp/help-en.html" 

== Screenshots ==

1. The new field on login page
1. An example of my MSL Secure Card
1. The new bulk action on users admin screen (javascript needed)
1. Same without javascript activated.
1. New button added to your profile when you need another MSL Secure Card

== Changelog ==

= 1.0.4 =
* 30 oct 2012
* Bug fix, a path was printed over the "powered by", my bad!

= 1.0.3 =
* 07 jun 2012
* PLEASE CHECK YOUR EMAIL SETTINGS IN YOUR PROFILE BEFORE LOGOUT THE FIRST TIME AND WAIT FOR THE MAIL CONTAINING THE SECURE CARD. THANK YOU

= 1.0.2 =
* 23 may 2012
* Externalize Help files
* Change the data/base64 image url into a real PNG image

= 1.0.1 =
* 25 mar 2012
* Fixing a possible bug when current_time('mysql') returns a bad date :/

= 1.0 =
* 06 feb 2012
* First release

= todo =
* A "Pro" version is already under construction, here comes some improvments:
* Option page
* Anti brute-force
* Limit login attempts
* Send self-email when someone logs into your account
* Force the disconnection and password reset for your account in case of threat
* Add the possibility to change the code length
* Force your users to set strong passwords
* Detect low passwords strenght
* Forbid double login
* Forbid users to manually change their password, ask for reset instead.
* Add the possibility to personnalize the picture output
* More hooks
* ...

== Upgrade Notice ==

None