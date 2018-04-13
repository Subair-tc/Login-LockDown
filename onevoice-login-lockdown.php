<?php
/* 
Plugin Name: Onevoice Login LockDown
Plugin URI: 
Version: 1.0
Author: Subair
Description: locking option for fialed login attepts.
*/

/* Set constant path to the plugin directory. */
//define( 'LOGIN_LOCKDOWN_MULTI_PATH', plugin_dir_path( __FILE__ ) );

/* Set constant url to the plugin directory. */
//define( 'LOGIN_LOCKDOWN_MULTI_URL', plugin_dir_url( __FILE__ ) );

/* Set the constant path to the plugin's includes directory. */
//define( 'LOGIN_LOCKDOWN_INC', LOGIN_LOCKDOWN_MULTI_PATH . trailingslashit( 'inc' ), true );


/* Set the constant path to the plugin's image directory. */
//define( 'LOGIN_LOCKDOWN_MULTI_IMAGES', LOGIN_LOCKDOWN_MULTI_PATH . trailingslashit( 'images' ), true );



$onevoice_loginlockdown_db_version = "1.0";
$loginlockdownOptions = get_login_lockdown_options();

/* Runs when plugin is activated */
register_activation_hook(__FILE__,'onevoice_lockdown_plugin_activate'); 
function onevoice_lockdown_plugin_activate() {
    global $wpdb;
	global $onevoice_loginlockdown_db_version;

    $table_name = $wpdb->prefix . "ov_login_fails";

	if( $wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name ) {
		$sql = "CREATE TABLE " . $table_name . " (
			`login_attempt_ID` bigint(20) NOT NULL AUTO_INCREMENT,
			`user_id` bigint(20) NOT NULL,
			`login_attempt_date` datetime NOT NULL default '0000-00-00 00:00:00',
			`login_attempt_IP` varchar(100) NOT NULL default '',
			PRIMARY KEY  (`login_attempt_ID`)
			);";

		require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
		dbDelta($sql);
	}

	$table_name = $wpdb->prefix . "ov_lockdowns";

	if( $wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name ) {
		$sql = "CREATE TABLE " . $table_name . " (
			`lockdown_ID` bigint(20) NOT NULL AUTO_INCREMENT,
			`user_id` bigint(20) NOT NULL,
			`lockdown_date` datetime NOT NULL default '0000-00-00 00:00:00',
			`release_date` datetime NOT NULL default '0000-00-00 00:00:00',
			`lockdown_IP` varchar(100) NOT NULL default '',
			PRIMARY KEY  (`lockdown_ID`)
			);";

		require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
		dbDelta($sql);
	}
	add_option("onevoice_loginlockdown_db_version", "1.0", "", "no");
}


function ov_login_fails_count($username = "") {
	global $wpdb;
    global $loginlockdownOptions;

	$table_name = $wpdb->prefix . "ov_login_fails";
	$subnet = ov_calc_subnet($_SERVER['REMOTE_ADDR']);

	$numFailsquery = "SELECT COUNT(login_attempt_ID) FROM $table_name " . 
					"WHERE login_attempt_date + INTERVAL " .
					$loginlockdownOptions['retries_within'] . " MINUTE > now() AND " . 
					"login_attempt_IP LIKE '%s'";
	$numFailsquery = $wpdb->prepare( $numFailsquery, $subnet[1]  . "%");

	$numFails = $wpdb->get_var($numFailsquery);
	return $numFails;
}


function ov_incrementFails($username = "") {
	global $wpdb;
	global $loginlockdownOptions;
	$table_name = $wpdb->prefix . "ov_login_fails";
	$subnet = ov_calc_subnet($_SERVER['REMOTE_ADDR']);

	$username = sanitize_user($username);


	if ( ! filter_var( $username, FILTER_VALIDATE_EMAIL ) === false ) {
		$user = get_user_by( 'email', $username );

	} else {
		$user = get_user_by('login',$username);
	}
	if ( $user || "yes" == $loginlockdownOptions['lockout_invalid_usernames'] ) {
		if ( $user === false ) { 
			$user_id = -1;
		} else {
			$user_id = $user->ID;
		}
		$insert = "INSERT INTO " . $table_name . " (user_id, login_attempt_date, login_attempt_IP) " .
				"VALUES ('" . $user_id . "', now(), '%s')";
		$insert = $wpdb->prepare( $insert, $subnet[0] );
		$results = $wpdb->query($insert);
	}

	return $results;
}

function ov_lockDown($username = "") {
	global $wpdb;
	global $loginlockdownOptions;
	$table_name = $wpdb->prefix . "ov_lockdowns";
	$subnet = ov_calc_subnet($_SERVER['REMOTE_ADDR']);

	$username = sanitize_user($username);
	if ( ! filter_var( $username, FILTER_VALIDATE_EMAIL ) === false ) {
		$user = get_user_by( 'email', $username );

	} else {
		$user = get_user_by('login',$username);
	}
	if ( $user || "yes" == $loginlockdownOptions['lockout_invalid_usernames'] ) {
		if ( $user === false ) { 
			$user_id = -1;
		} else {
			$user_id = $user->ID;
		}
		$insert = "INSERT INTO " . $table_name . " (user_id, lockdown_date, release_date, lockdown_IP) " .
				"VALUES ('" . $user_id . "', now(), date_add(now(), INTERVAL " .
				$loginlockdownOptions['lockout_length'] . " MINUTE), '%s')";
		$insert = $wpdb->prepare( $insert, $subnet[0] );
		$results = $wpdb->query($insert);
	}
}

function ov_isLockedDown() {
	global $wpdb;
	$table_name = $wpdb->prefix . "ov_lockdowns";
	$subnet = ov_calc_subnet($_SERVER['REMOTE_ADDR']);

	$stillLockedquery = "SELECT user_id FROM $table_name " . 
					"WHERE release_date > now() AND " . 
					"lockdown_IP LIKE %s";
	$stillLockedquery = $wpdb->prepare($stillLockedquery,$subnet[1] . "%");

	$stillLocked = $wpdb->get_var($stillLockedquery);

	return $stillLocked;
}

function ov_listLockedDown() {
	global $wpdb;
	$table_name = $wpdb->prefix . "ov_lockdowns";

	$listLocked = $wpdb->get_results("SELECT lockdown_ID, floor((UNIX_TIMESTAMP(release_date)-UNIX_TIMESTAMP(now()))/60) AS minutes_left, ".
					"lockdown_IP FROM $table_name WHERE release_date > now()", ARRAY_A);

	return $listLocked;
}


function ov_calc_subnet($ip) {
	$subnet[0] = $ip;
	if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
		$ip = ov_expandipv6($ip);
		preg_match("/^([0-9abcdef]{1,4}:){4}/", $ip, $matches);
		$subnet[0] = $ip;
		$subnet[1] = $matches[0];
	} else {
		$subnet[1] = substr ($ip, 0 , strrpos ( $ip, "." ) + 1);
	}
	return $subnet;
}
function ov_expandipv6($ip){
	$hex = unpack("H*hex", inet_pton($ip));         
	$ip = substr(preg_replace("/([A-f0-9]{4})/", "$1:", $hex['hex']), 0, -1);

	return $ip;
}



function get_login_lockdown_options() {
	$loginlockdownAdminOptions = array(
		'max_login_retries' => 10,
		'retries_within' => 5,
		'lockout_length' => 10,
		'lockout_invalid_usernames' => 'no',
		'lockout_errormessage' => "We're sorry, but this IP has been blocked due to too many failed login attempts",
	);
	$loginlockdownOptions = get_option("loginlockdownAdminOptions");
	
	if ( !empty($loginlockdownOptions) ) {
		foreach ( $loginlockdownOptions as $key => $option ) {
			$loginlockdownAdminOptions[$key] = $option;
		}
	}
	update_option("loginlockdownAdminOptions", $loginlockdownAdminOptions);
	return $loginlockdownAdminOptions;
}

add_filter( 'plugin_action_links_' . plugin_basename(__FILE__), 'login_lockdown__add_action_links' );

function login_lockdown__add_action_links ( $links ) {
	$mylinks = array(
	'<a href="' . admin_url( 'admin.php?page=onevoice-login-lockdown.php' ) . '">Settings</a>',
	);
	return array_merge( $links, $mylinks );
}


function onv_print_loginlockdownAdminPage() {
	global $wpdb;
	$table_name = $wpdb->prefix . "ov_lockdowns";
	$loginlockdownAdminOptions = get_login_lockdown_options();

	if (isset($_POST['update_loginlockdownSettings'])) {

			//wp_nonce check
			check_admin_referer('login-lockdown_update-options');

			if (isset($_POST['ll_max_login_retries'])) {
			$loginlockdownAdminOptions['max_login_retries'] = $_POST['ll_max_login_retries'];
			}
			if (isset($_POST['ll_retries_within'])) {
			$loginlockdownAdminOptions['retries_within'] = $_POST['ll_retries_within'];
			}
			if (isset($_POST['ll_lockout_length'])) {
			$loginlockdownAdminOptions['lockout_length'] = $_POST['ll_lockout_length'];
			}
			if (isset($_POST['ll_lockout_invalid_usernames'])) {
				$loginlockdownAdminOptions['lockout_invalid_usernames'] = $_POST['ll_lockout_invalid_usernames'];
			}

			if (isset($_POST['ll_lockout_errormessage'])) {
				$loginlockdownAdminOptions['lockout_errormessage'] = wp_unslash( $_POST['ll_lockout_errormessage'] );
			}

			update_option("loginlockdownAdminOptions", $loginlockdownAdminOptions);
			?>
			<div class="updated"><p><strong><?php _e("Settings Updated.", "loginlockdown");?></strong></p></div>
		<?php
	}

	if (isset($_POST['release_lockdowns'])) {

		//wp_nonce check
		check_admin_referer('login-lockdown_release-lockdowns');

		if (isset($_POST['releaseme'])) {
			$released = $_POST['releaseme'];
			foreach ( $released as $release_id ) {
				$releasequery = "UPDATE $table_name SET release_date = now()  WHERE lockdown_ID = '%d'";
				$releasequery = $wpdb->prepare($releasequery,$release_id);
				$results = $wpdb->query($releasequery);
			}
		}
		update_option("loginlockdownAdminOptions", $loginlockdownAdminOptions);
		?>
<div class="updated"><p><strong><?php _e("Lockdowns Released.", "loginlockdown");?></strong></p></div>
		<?php
	}


	$dalist = ov_listLockedDown();
?>
<div class="wrap">
<?php
	
$active_tab = isset( $_GET[ 'tab' ] ) ? $_GET[ 'tab' ] : 'settings';

?>
<h2><?php _e('Login LockDown Options', 'loginlockdown') ?></h2>

	<h2 class="nav-tab-wrapper">
		<a href="?page=onevoice-login-lockdown.php&tab=settings" class="nav-tab <?php echo $active_tab == 'settings' ? 'nav-tab-active' : ''; ?>">Settings</a>
		<a href="?page=onevoice-login-lockdown.php&tab=activity" class="nav-tab <?php echo $active_tab == 'activity' ? 'nav-tab-active' : ''; ?>">Activity (<?php echo count($dalist); ?>)</a>
	</h2>
<?php 
	if ( $active_tab == 'settings' ) { ?>
		
		<form method="post" action="<?php echo esc_attr($_SERVER["REQUEST_URI"]); ?>">
		<?php
			if ( function_exists('wp_nonce_field') ) {
				wp_nonce_field('login-lockdown_update-options');
			}	
		?>

			<h3><?php _e('Max Login Retries', 'loginlockdown') ?></h3>
			<p>Number of failed login attempts within the "Retry Time Period Restriction" (defined below) needed to trigger a LockDown.</p>
			<p><input type="text" name="ll_max_login_retries" size="8" value="<?php echo esc_attr($loginlockdownAdminOptions['max_login_retries']); ?>"></p>
			
			
			<h3><?php _e('Retry Time Period Restriction (minutes)', 'loginlockdown') ?></h3>
			<p>Amount of time that determines the rate at which failed login attempts are allowed before a LockDown occurs.</p>
			<p><input type="text" name="ll_retries_within" size="8" value="<?php echo esc_attr($loginlockdownAdminOptions['retries_within']); ?>"></p>
			
			
			<h3><?php _e('Lockout Length (minutes)', 'loginlockdown') ?></h3>
			<p>How long a particular IP block will be locked out for once a LockDown has been triggered.</p>
			<p><input type="text" name="ll_lockout_length" size="8" value="<?php echo esc_attr($loginlockdownAdminOptions['lockout_length']); ?>"></p>
			

			<h3><?php _e('Lockout Error Message', 'loginlockdown') ?></h3>
			<p>Error Message on lockout error</p>
			<p><textarea type="text" name="ll_lockout_errormessage" size="8" ><?php echo esc_attr($loginlockdownAdminOptions['lockout_errormessage']); ?></textarea></p>
			
			
			<h3><?php _e('Lockout Invalid Usernames?', 'loginlockdown') ?></h3>
			<p>By default Login LockDown will not trigger if an attempt is made to log in using a username that does not exist. You can override this behavior here.</p>
			<p><input type="radio" name="ll_lockout_invalid_usernames" value="yes" <?php if( $loginlockdownAdminOptions['lockout_invalid_usernames'] == "yes" ) echo "checked"; ?>>&nbsp;Yes&nbsp;&nbsp;&nbsp;<input type="radio" name="ll_lockout_invalid_usernames" value="no" <?php if( $loginlockdownAdminOptions['lockout_invalid_usernames'] == "no" ) echo "checked"; ?>>&nbsp;No</p>
			
			<div class="submit">
				<input type="submit" class="button button-primary" name="update_loginlockdownSettings" value="<?php _e('Update Settings', 'loginlockdown') ?>" />
			</div>
			
		</form>
<?php 
	} else { ?>
	<form method="post" action="<?php echo esc_attr($_SERVER["REQUEST_URI"]); ?>">
		<?php
		if ( function_exists('wp_nonce_field') )
			wp_nonce_field('login-lockdown_release-lockdowns');
		?>
		<h3><?php 
		if( count($dalist) == 1 ) {
			printf( esc_html__( 'There is currently %d locked out IP address.', 'loginlockdown' ), count($dalist) ); 

		} else {
			printf( esc_html__( 'There are currently %d locked out IP addresses.', 'loginlockdown' ), count($dalist) ); 
		} ?></h3>

		<?php
			$num_lockedout = count($dalist);
			if( 0 == $num_lockedout ) {
				echo "<p>No IP blocks currently locked out.</p>";
			} else {
				foreach ( $dalist as $key => $option ) {
					?>
						<li><input type="checkbox" name="releaseme[]" value="<?php echo esc_attr($option['lockdown_ID']); ?>"> <?php echo esc_attr($option['lockdown_IP']); ?> (<?php echo esc_attr($option['minutes_left']); ?> minutes left)</li>
					<?php
				}
			}
		?>
		<div class="submit">
			<input type="submit" class="button button-primary" name="release_lockdowns" value="<?php _e('Release Selected', 'loginlockdown') ?>" />
		</div>
	</form>
<?php } ?>
</div>
<?php
}//End function print_loginlockdownAdminPage()

add_action('admin_menu', 'onv_loginlockdown_ap');

function onv_loginlockdown_ap() {
	if ( function_exists('add_options_page') ) {
		add_options_page('Login LockDown', 'Login LockDown', 'manage_options', basename(__FILE__), 'onv_print_loginlockdownAdminPage');
	}
}