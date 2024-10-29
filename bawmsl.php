<?php
/*
Plugin Name: BAW More Secure Login
Plugin URI: http://boiteaweb.fr/msl
Description: Add a new field below password to improve security and prove that you are physically trying to log in.
Version: 1.0.4
Author: Juliobox
Author URI: http://boiteaweb.fr
License: GPLv2
TextDomain: bawmsl
DomainPath: /lang
*/

DEFINE( 'BAWMSL_PLUGIN_URL', trailingslashit( WP_PLUGIN_URL ) . basename( dirname( __FILE__ ) ) );

/**
* Init the translation
**/
// function bawmsl_l10n_init()
// {
  // load_plugin_textdomain( 'bawmsl', '', dirname( plugin_basename( __FILE__ ) ) . '/lang' );
// }
// add_action( 'init','bawmsl_l10n_init' );

if( !is_admin() ) {
	/** 
	* Insert the random hash in DB
	* Empty the TABLE from olf hashes
	* Add the MSL field to the Login Form
	*
	* @hook 'bawmsl_inputprops' filter 1 param: $input_props (array) you can overwrite the input's properties except "name"
	*
	**/
	function bawmsl_login_form_add_field()
	{
		global $wpdb;
		$hash = md5( time() . rand() );
		$table_name = $wpdb->prefix . 'moresecurelogin';
		$col = chr( rand( 1, 8 ) + 64 );
		$row = rand( 1, 8 );
		// Insert a random hash associated with a code couple, like A1
		$wpdb->insert( $table_name, array( 'timestamp' => date( 'Y-m-d H:i:s' ), 'code' => $col.$row, 'hash' => $hash ) ); 
		// Delete all hash if generated 5mn or more earlier
		$wpdb->query( 'DELETE FROM ' . $table_name . ' WHERE timestamp < "' . date( 'Y-m-d H:i:s', mktime( date( 'H' ), date( 'i' ) - 5, date( 's' ), date( 'n' ), date( 'j' ), date( 'Y' ) ) ) . '"' ); // 5 mn
		$input_props = array( 	'type' => 'text',
								'id' => 'mslcode',
								'class' => 'input',
								'value' => '',
								'autocomplete' => 'off',
								'placeholder' => __( 'Required code: ', 'bawmsl' ) . $col.$row,
								'tabindex' => '89',
								'style' => ''
							);
		$input_props = apply_filters( 'bawmsl_inputprops', $input_props );
	 ?>    
		<p id="bawmsl">
		  <label>
			More Secure Login <?php _e( 'Code', 'bawmsl' ) ?> <strong><?php echo $col.$row; ?></strong> <a href="http://baw.li/mslhelp/help-<?php _e( 'en', 'bawmsl' ); ?>.html" target="_blank"><img src="<?php echo BAWMSL_PLUGIN_URL; ?>/images/help.png" alt="<?php _e( 'Need help?', 'bawmsl' ); ?>" title="<?php _e( 'Need help?', 'bawmsl' ); ?>" /></a><br />
			<?php
			if( isset( $input_props['name'] ) ) unset( $input_props['name'] ); // Do not overwrite the name.
			$input = '<input name="mslcode" ';
			foreach( $input_props as $name=>$value ) {
				$input .= esc_html( $name ) . '="' . esc_attr( $value ) . '" ';
			}
			$input .= ' />';
			echo $input;
			?>
		  </label>
		  <?php /* 	Please do not remove it! This link is not present in the "Pro" version. 
					You can also give us a paypal donation : https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=KJGT942XKWJ6W
				*/ ?>
		  <span style="font-size:xx-small;font-style:italic;position:relative;top:-15px;"><?php _e( 'Powered by', 'bawmsl' ); ?> <a href="http://baw.li/msl">BAW More Secure Login</a>.</span>
		  <input type="hidden" name="mslhash" id="mslhash" value="<?php echo $hash; ?>" /></label>
		</p>
	 <?php
	}
	add_action( 'login_form', 'bawmsl_login_form_add_field' );
	
	/** 
	* Filter a string to avoid confusion with 1/i/l/I, 0/O/o, 5/S, can be overwriten with the hook filter
	*
	* @param user_object $raw_user The user object
	* @param string $username The user name
	*
	* @return object If no error, a user object is returned, else, a wp_error object is returned
	**/
	function bawmsl_authenticate( $raw_user, $username )
	{
		if( isset( $_POST['mslcode'], $_POST['mslhash'] ) ) {
			$user = get_user_by( 'login', $username );
			if( $user ) // User is found
			{
				global $wpdb;
				$table_name = $wpdb->prefix . 'moresecurelogin';
				$code = $wpdb->get_var( $wpdb->prepare( 'SELECT code FROM ' . $table_name . ' WHERE hash = %s', $_POST['mslhash'] ) );
				$codes = (array)get_user_meta( $user->ID, 'bawmsl_codes', true );
				if( !$code || !wp_check_password( bawmsl_filter( $_POST['mslcode'] ), $codes[$code], '' ) ) // MSL code is not valid
				{
					add_action( 'login_head', 'wp_shake_js', 12 );
					return new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: Invalid MSL code.', 'bawmsl' ) );
				}
			}
		}else // MSL code has not been sent
		if( isset( $_POST['log'], $_POST['pwd'] ) ) {
			add_action( 'login_head', 'wp_shake_js', 12 );
			return new WP_Error( 'authentication_failed', __( '<strong>ERROR</strong>: MSL code missing.', 'bawmsl' ) );
		}
		return $raw_user;
	}
	add_filter( 'authenticate', 'bawmsl_authenticate', 999, 2 );	
}
/** 
* Explode a 256c string into an special array
*
* @param string $str 256c. are needed
*
* @return Array Contains all codes sorted from A1 to H8
**/
function bawmsl_explode( $str )
{
	  $arr = array();
	  $col = 'A';
	  $lig = 1;
	  for( $i = 1 ; $i <= 64 ; $i++ ) {
			$arr[$col.$lig] = substr( $str, ( $i - 1 ) * 4, 4 );
			if( $i % 8 == 0 )
				$lig++;
			$col++;
			if( $i % 8 == 0 )
				$col = 'A';
	  }
	  return $arr;
}

/** 
* Filter a string to avoid confusion with 1/i/l/I, 0/O/o, 5/S, can be overwriten with the hook filter
*
* @param string $string The string to be filtered
*
* @hook 'bawmsl_filter' filter 2 params : $result: the filtered string - $string: the original string
*
* @return string Contains the string filtered
**/
function bawmsl_filter( $string )
{
	$result = str_ireplace( array( 'i', 'l', 's', 'o' ), array( '1', '1', '5', '0' ), $string );
	$result = strtoupper( $result );
	// HOOK 'bawmsl_filter'
	$result = apply_filters( 'bawmsl_filter', $result, $string );
	return $result;
}

/**
 * Notify the blog admin of a user changing password, normally via email.
 *
 * @since 2.7
 *
 * @param object $user User Object
 */
 /** 
* Overwritten by BAWMSL
*
*Now sent the car to the user too
**/
 if ( !function_exists('wp_password_change_notification') ) :
function wp_password_change_notification( &$user ) {
	$message = sprintf( __( 'Password Lost and Changed for user: %s' ), $user->user_login) . "\r\n";
	$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
	// Email the admin
	@wp_mail( get_option( 'admin_email' ), sprintf( __( '[%s] Password Lost/Changed' ), $blogname ), $message );

	$user_email = stripslashes( $user->user_email );
	// Generate the file
	$file = bawmsl_generate_card( $user, 'update' );
	$message = sprintf( __( 'You just changed your password, a new MSL Secure Card has been generated for you %s.', 'bawmsl' ), $user->user_nicename ) . "\r\n";
	$message .= __( 'Your MSL Secure Card:', 'bawmsl' ) . "\r\n";
	$message .= __( '(See attached file)', 'bawmsl' ) . "\r\n\r\n";
	$message .= __( 'Powered by:', 'bawmsl' ) . '<a href="http://baw.li/msl">BAW More Secure Login</a> (http://baw.li/msl)';
	// Email the user its card
	@wp_mail( $user_email, sprintf( __( '[%s] Your MSL Secure Card is ready', 'bawmsl' ), $blogname), $message, 'content-type: text/html', $file );
	// Delete the file
	unlink( $file );
}
endif;

/** 
* Send an email to site admin
* Send an email to the user, containing either a html or png file
*
* @param user_object $user The user for whom we generate and send a MSL Secure Card by email
**/
function bawmsl_mail_renew_secure_card( $user ) {
	$message = sprintf( __( 'New MSL Secure Card for user: %s', 'bawmsl' ), $user->user_login ) . "\r\n";
	$blogname = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
	// Email the admin
	@wp_mail( get_option( 'admin_email' ), sprintf( __( '[%s] New MSL Secure Card asked', 'bawmsl' ), $blogname ), $message );

	$user_email = stripslashes($user->user_email);
	// Generate the file
	$file = bawmsl_generate_card( $user, 'update' );
	$message = sprintf( __( 'A new MSL Secure Card has been generated for you %s.', 'bawmsl' ), $user->user_nicename ) . "\r\n";
	$message .= __( 'Your MSL Secure Card:', 'bawmsl' ) . "\r\n";
	$message .= __( '(See attached file)', 'bawmsl' ) . "\r\n\r\n";
	$message .= __( 'Powered by:', 'bawmsl' ) . ' <a href="http://baw.li/msl">BAW More Secure Login</a> (http://baw.li/msl)';
	// Email the user its card
	@wp_mail( $user_email, sprintf( __( '[%s] Your MSL Secure Card is ready', 'bawmsl' ), $blogname ), $message, 'content-type: text/html', $file );
	// Delete the file
	unlink( $file );
}

/**
 * Notify the blog admin of a new user, normally via email.
 *
 * @since 2.0
 *
 * @param int $user_id User ID
 * @param string $plaintext_pass Optional. The user's plaintext password
 */
  /** 
* Overwritten by BAWMSL
*
* Now send the card to the user too
**/
if ( !function_exists('wp_new_user_notification') ) :
function wp_new_user_notification($user_id, $plaintext_pass = '') {
	$user = new WP_User($user_id);
	$user_login = stripslashes($user->user_login);
	$user_email = stripslashes($user->user_email);
	$blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);

	$message  = sprintf( __( 'New user registration on your site %s:' ), $blogname ) . "\r\n\r\n";
	$message .= sprintf( __( 'Username: %s'), $user_login ) . "\r\n\r\n";
	$message .= sprintf( __( 'E-mail: %s'), $user_email ) . "\r\n";
	// Email the admin
	@wp_mail( get_option( 'admin_email' ), sprintf( __( '[%s] New User Registration' ), $blogname ), $message );

	if ( empty( $plaintext_pass ) )
		return;
	// Generate the file
	$file = bawmsl_generate_card( $user, 'add' );
	$message  = sprintf( __( 'Username: %s' ), $user_login ) . "\r\n";
	$message .= sprintf( __( 'Password: %s' ), $plaintext_pass ) . "\r\n";
	$message .= wp_login_url() . "\r\n";
	// Email the user its login/password
	@wp_mail( $user_email, sprintf( __( '[%s] Your username and password' ), $blogname ), $message );

	$message = __( 'Your MSL Secure Card:', 'bawmsl' ) . "\r\n";
	$message .= __( '(See attached file)', 'bawmsl' ) . "\r\n\r\n";
	$message .= __( 'Powered by:', 'bawmsl' ) . '<a href="http://baw.li/msl">BAW More Secure Login</a> (http://baw.li/msl)';
	// Email the user its card
	@wp_mail( $user_email, sprintf( __( '[%s] Your MSL Secure Card is ready', 'bawmsl' ), $blogname ), $message, 'content-type: text/html', $file );
	// Delete the file
	unlink( $file );
}
endif;

/** 
* Generate either a png file (if GD lib installed) or html file (if not)
* This file contains the MSL Secure Card
*
* @param string $codes The users generated codes from meta datas
*
* @return string The generated filename
**/
function bawmsl_generate_card_picture( $codes )
{
	$lcodes = str_split( $codes, 32 );
	$uploads = wp_upload_dir();
	$filename = $uploads['basedir'] . '/' . md5( time() . rand() ) ;
	if( extension_loaded( 'gd' ) && function_exists( 'imagepng' ) ) { // GD installed
		$extension = '.png';
		$image = imagecreate( 350, 220 );
		$color_bg = imagecolorallocate( $image, 255, 255, 255 ); // Background Color
		$color_fg = imagecolorallocate( $image, 0, 0, 0 ); // Foreground color
		$color_hd = imagecolorallocate( $image, 0, 0, 255 ); // Header color
		$i = 0;
		imagestring($image, 4, 1, (15*$i)+15, '[#] [A ] [B ] [C ] [D ] [E ] [F ] [G ] [H ]', $color_hd); // Write the header
		foreach( $lcodes as $code ) {
			$i++;
			$code = implode( ' ', str_split( $code, 4 ) );
			imagestring($image, 4, 1, (15*$i)+15, '['.$i.'] ' . $code, $color_fg); // Write each code line
		}
		$blogname = wp_specialchars_decode( get_option( 'blogname') , ENT_QUOTES );
		imagestring($image, 4, 1, (15*($i+2))+15, __( 'MSL Secure Card for:', 'bawmsl' ), $color_hd); // Write some infos
		imagestring($image, 4, 1, (15*($i+3))+15, $blogname, $color_hd); //
		imagestring($image, 4, 1, (15*($i+4))+15, site_url() . '/wp-admin/', $color_hd); //
		imagepng( $image, $filename . $extension, 0 ); // Create the PNG image
	}else{ // GD not installed
		$blogname = wp_specialchars_decode( get_option( 'blogname') , ENT_QUOTES );
		$i = 1;
		$extension = '.html';
		// $table contains the HTML code
		$table  = '<html><head><title>' . __( 'MSL Secure Card for:', 'bawmsl' ) . ' ' . $blogname . '</title>';
		$table .= '<style>
					body{background-color:#FFFFFF;font-family:system;}
					tr{text-align:center;}
					.odd{background-color:#EEEEEE}
					.cccccc{background-color:#CCCCCC}
				   </style>';
		$table .= '</head><body>';
		$table .= '<table border="1" callspacing="2" callpadding="2"><thead class="cccccc"><tr><td>#</td><td>A</td><td>B</td><td>C</td><td>D</td><td>E</td><td>F</td><td>G</td><td>H</td></tr></thead><tbody>';
		foreach( $lcodes as $code ) {
			$class = $i % 2 == 0 ? 'odd' : '';
			$table .= '<tr><td class="cccccc">#' . $i . '</td>';
			$code = str_split( $code, 4 );
			foreach( $code as $c ) {
				$table .= '<td>' . $c . '</td>';
			}
			$table .= '</tr>';
			$i++;
		}
		$table .= '</tbody></table><p><a href="' . admin_url() . '/">' . $blogname . '</a></p></body></html>';
		$file = fopen( $filename . $extension, 'a'); // Create the HTML file
		fputs( $file, $table );
		fclose( $file );
	}
	return $filename . $extension;
}

/** 
* Generate random codes for all or one user
*
* @hook 'bawmsl_chars' filter, 1 param containing the chars used for the codes generation
* @hook 'bawmsl_generated_card' action, 1 param: $user: the user object
*
* @param string/int $user_id Contains a user object
**/
function bawmsl_generate_card( $user, $action )
{
	$chars = apply_filters( 'bawmsl_chars', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' );
	if( !is_object( $user ) ) continue;
	$codes = '';
	for ( $i = 0; $i < 256; $i++ ) {
		$codes .= substr($chars, rand(0, strlen($chars) - 1), 1);
	}
	$pic_codes = bawmsl_filter( $codes );
	$codes = bawmsl_explode( bawmsl_filter( $codes ) );
	$codes = array_map( 'wp_hash_password', $codes );
	switch( $action ) {
		case 'add' : if( get_user_meta ( $user->ID, 'bawmsl_codes', true ) == '' ) add_user_meta( $user->ID, 'bawmsl_codes', $codes ); break;
		case 'update' :
		default :  update_user_meta( $user->ID, 'bawmsl_codes', $codes ); break;
	}
	do_action( 'bawmsl_generated_card', $user );
	return bawmsl_generate_card_picture( $pic_codes );
}

if( is_admin() ) {
	/** 
	* Display a button to renew you card manually if you lost it but can still get access to your profile
	*
	* @param user_object $profileuser
	**/
	function bawmsl_personal_options( $profileuser )
	{
		if( isset( $_GET['user_id'] ) ) return ''; // Do not display the renew button on user editing
		?>
		<tr class="get-new-msl-secure-card">
		<th scope="row"><?php _e( 'Get a new MSL Secure Card', 'bawmsl' )?></th>
		<td><fieldset><legend class="screen-reader-text"><span><?php _e( 'Get a new MSL Secure Card', 'bawmsl' ) ?></span></legend>
		<label for="get-new-msl-secure-card">
		<?php
		if( !isset( $_GET['renew_secure_card'] ) || !wp_verify_nonce( $_GET['renew_secure_card'], 'renew_secure_card' ) ) {
			?>
			<a class="button-primary" href="<?php echo esc_url( admin_url( 'profile.php' ) . '?renew_secure_card=' . wp_create_nonce( 'renew_secure_card' ) ); ?>"><?php _e ('New MSL Secure Card', 'bawmsl' ); ?></a>
			<?php _e( '<em>You will receive it by e-mail.</em>', 'bawmsl' ); ?></label></form><br />
			<?php
		}else{ 
			bawmsl_mail_renew_secure_card( $profileuser );
			echo '<b>' . __( 'New MSL Card generated and sent my email.', 'bawmsl' ) . ' ' . __( 'Please check it now !', 'bawmsl' ) . '</b>';
		} ?>
		</fieldset>
		</td>
		</tr>
		<?php 
	}
	add_action( 'personal_options', 'bawmsl_personal_options', 10, 1 );

	/** 
	* Add a link in the user actions on users list (hidden if JS)
	* Generate and send new MSL Secure Card by email
	* 
	* @param array $actions The actions links
	* @param array $user The user object
	*
	* @return array $actions Contains the actions links
	**/
	function bawmsl_user_row_actions( $actions, $user )
	{
		// Security and check if 1 user has to be regenerated
		if( isset( $_GET['_wpnonce'], $_GET['action'], $_GET['user'] ) && $_GET['action']=='regenmslcard' && (int)$_GET['user']>0 && $_GET['user'] == $user->ID && wp_verify_nonce( $_GET['_wpnonce'], 'bawmsl-regencard_' . $user->ID ) ) {
			bawmsl_mail_renew_secure_card( $user );
			echo '<div class="updated hide-if-no-js"><p>' . __( 'New MSL Card generated and sent my email.', 'bawmsl' ) . '</p></div>';
			$actions['bawmsl'] = '<b>' . __( 'New MSL Card generated and sent my email.', 'bawmsl' ) . '</b>';
		}else // Same but with more users (bulk actions)
		if( isset( $_GET['_wpnonce'], $_GET['action'], $_GET['users'] ) && $_GET['action']=='regenmslcard' && is_array( $_GET['users'] ) && count( $_GET['users'] )>0 && wp_verify_nonce( $_GET['_wpnonce'], 'bulk-users' ) ) {
			foreach( $_GET['users'] as $luser ) {
				if( $luser == $user->ID )
					$actions['bawmsl'] = '<b>' . __( 'New MSL Card generated and sent my email.', 'bawmsl' ) . '</b>';
			}
		}else{ // Noone, just add the link
			$url = wp_nonce_url( admin_url( 'users.php?action=regenmslcard&user=' . $user->ID ), 'bawmsl-regencard_' . $user->ID );
			$actions['bawmsl'] = '<span class="hide-if-js"><a href="'.esc_url( $url ).'">' .  __( 'Regen. MSL Secure Card', 'bawmsl' ) . '</a></span>';
		}
		return $actions;
	}
	add_action( 'user_row_actions', 'bawmsl_user_row_actions', 10, 2 );

	/** 
	* Add jQuery code for users.php page
	* Generate and send new MSL Secure Card by email
	**/
	function bawmsl_admin_head_users_bulk_action()
	{
		// Security and check if some users have to be regenerated
		if( isset( $_GET['_wpnonce'], $_GET['action'], $_GET['users'] ) && $_GET['action']=='regenmslcard' && is_array( $_GET['users'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'bulk-users' ) ) {
			foreach( $_GET['users'] as $luser ) {
				$luser = get_user_by( 'id', $luser );
				bawmsl_mail_renew_secure_card( $luser );
			}
			echo '<div class="updated hide-if-no-js"><p>' . __( 'New MSL Cards generated and sent my email.', 'bawmsl' ) . '</p></div>';
		}
		// jQuery code to add a bulk action and catch the submit
		// jQuery( 'form[method="get"] input[name="_wp_http_referer"]').remove(); => to keep the _wpnonce and avoid the "case default" redirection!
	?>
	<script>
	jQuery(document).ready(function(){
		jQuery( 'select[name="action"],select[name="action2"]' ).append( '<option value="regenmslcard"><?php echo strip_tags( esc_html( __( 'Regen. MSL Secure Card', 'bawmsl' ) ) ); ?></option>' );
		jQuery( 'form[method="get"]' ).submit( function(e){
			if( jQuery( 'select[name="action"]' ).val() == 'regenmslcard' || ( jQuery( 'select[name="action2"]' ).val() == 'regenmslcard' && jQuery( 'select[name="action"]' ).val() == '-1' ) ) {
				e.preventDefault();
				if( jQuery( 'input[name="users[]"]:checked' ).length > 9 && !confirm( "<?php addslashes( esc_js( __( 'Are you sure to renew all these cards ? More than 10 may take a long time ...', 'bawmsl' ) ) ); ?>" ) )
					return false;
				jQuery( 'form[method="get"] input[name="_wp_http_referer"]').remove();
				location.href='<?php echo esc_url( admin_url( 'users.php' ) ); ?>?' + jQuery( 'form[method="get"]' ).serialize();
			}
		} );
	});
	</script>
	<?php
	}
	add_action( 'admin_head-users.php', 'bawmsl_admin_head_users_bulk_action' );

	/** 
	* Installation of the plugin :
	* - Check if the UPLOAD dir is writable
	* - Create the new TABLE
	* - Generate and send the file by email
	**/
	function bawmsl_activation()
	{
		$uploads = wp_upload_dir();
		if ( !is_writable( $uploads['basedir'] ) ) { // if UPLOAD dir is not writable, we do not install the plugin
			deactivate_plugins( basename( __FILE__ ) );
			wp_die( __( 'The "uploads" folder needs to be writable !', 'bawmsl' ) );
		}
		global $wpdb, $current_user;
		$table_name = $wpdb->prefix . 'moresecurelogin';
		if( $wpdb->get_var( 'SHOW TABLES LIKE "' . $table_name .'"' ) != $table_name ) {
			$sql = 'CREATE TABLE '. $table_name . ' (
				id bigint(20) NOT NULL AUTO_INCREMENT,
				timestamp datetime DEFAULT "0000-00-00 00:00:00" NOT NULL,
				hash varchar(32) NOT NULL,
				code varchar(4) NOT NULL,
				UNIQUE KEY id (id)
			);';
			require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
			dbDelta( $sql ); // Creation of the new TABLE
		}
		bawmsl_mail_renew_secure_card( $current_user ); // Generation + mail of the Secure Card for you (the user whom activating the plugin)
	}
	register_activation_hook( __FILE__, 'bawmsl_activation' );

	/** 
	* Empty the table on deactivation
	**/
	function bawmsl_deactivation()
	{
	   global $wpdb;
	   $table_name = $wpdb->prefix . 'moresecurelogin';
	   $wpdb->query( 'TRUNCATE TABLE ' . $table_name );
	}
	register_deactivation_hook( __FILE__, 'bawmsl_deactivation' );

	/** 
	* Delete the table on deactivation
	* Delete all user meta too
	**/
	function bawmsl_uninstall()
	{
		global $wpdb;
		$table_name = $wpdb->prefix . 'moresecurelogin';
		$wpdb->query( 'DROP TABLE ' . $table_name );
		$wpdb->query( 'DELETE FROM ' . $wpdb->usermeta . ' WHERE meta_key = "bawmsl_codes"' );
	}
	register_uninstall_hook( __FILE__, 'bawmsl_uninstall' );
}

?>