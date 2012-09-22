<?php

$admin = array('root', 'fromano');
/* if secure_auth is false
 * 	try to bind uid=<username>,dn with a ldap server at host:port
 * else
 *	send password to sauthpf-daemon
 */
$secure_auth = true;
$ldapconfig['host'] = "localhost";
$ldapconfig['port'] = 389;
$ldapconfig['uid'] = 'uid';
$ldapconfig['dn'] = 'ou=Users,dc=local,dc=com';


$_LANGUAGES = array(
	'EN'	=> 'en_US', 
	'FR'	=> 'fr_FR'
);

if(isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) && in_array(strtoupper(substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2)), array_keys($_LANGUAGES)))
	$CLIENT_LANG = $_LANGUAGES[strtoupper(substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2))];
else
	$CLIENT_LANG = 'en_US';

putenv("LANG=".$CLIENT_LANG);
setlocale(LC_ALL, $CLIENT_LANG);
setlocale(LC_MESSAGES, $CLIENT_LANG.".utf8");
$lang_filenames = "locale";
bindtextdomain($lang_filenames, "./locale");
textdomain($lang_filenames);


function try_auth($user, $pass) {
	global $ldapconfig;
	$ldapconn = ldap_connect($ldapconfig['host'], $ldapconfig['port'])
	    or die(_("Could not connect to ").$ldaphost);
	ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);

	$ldapbind = ldap_bind($ldapconn,
	    $ldapconfig['uid'].'='.$user.','.$ldapconfig['dn'],
	    $pass);

	// verify binding
	if ($ldapbind) {
		return true;
	} else {
		return false;
	}
}

function redirect($page)
{
	header("Location: {$page}");
	exit;
}

function getip()
{
	if ( isset($_SERVER['HTTP_X_FORWARDED_FOR']) )
		$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
	else
		$ip = $_SERVER['REMOTE_ADDR'];
	return $ip;
}


sauthpf_init("./sauthpf.conf") or die("Could not init sauthpf");

if (isset($_GET['clientaddr']))
	$ip = $_GET['clientaddr'];
else
	$ip = getip();

$auth = sauthpf_isauth($ip);
if ($auth) {
	$user = $auth[0]['user'];
} else {
	$user = false;
}

/* SUID real proxy auth !
if (isset($_GET['clientuser']) && $_GET['clientuser'] != $user) {
	die(_("User associated with IP != user in squid. Strange error : REPORT this to your administrator"));
}
*/

if (isset($_POST['auth']) && isset($_POST['user']) && isset($_POST['pass'])) {
	if (!$secure_auth && try_auth($_POST['user'], $_POST['pass'])) {
		$auth = sauthpf_auth($_POST['user'], $ip);
		$user = $auth[0]['user'];
		if (isset($_POST['redirect_to']) && $_POST['redirect_to']) {
			redirect($_POST['redirect_to']);
		}
	} else if ($secure_auth) {
		if (($auth = sauthpf_auth($_POST['user'], $ip, $_POST['pass'])) !== false) {
			$user = $auth[0]['user'];
			if (isset($_POST['redirect_to']) && $_POST['redirect_to']) {
				redirect($_POST['redirect_to']);
			}
		} else {
			$error = _("Invalid username or password");
		}
	} else {
		$error = _("Invalid username or password");
	}
}

if (isset($_POST['unauth']) && $user) {
	sauthpf_unauth($ip, 1);
	$auth = false;
}

?>

<html>
	<head>
		<base href="https://<?=$_SERVER['SERVER_NAME']?><?=dirname($_SERVER['SCRIPT_NAME'])?>/" />
		<title><?=_("SauthPF : control web access page")?></title>
		<link type="text/css" href="./public/smoothness/jquery-ui-1.8.5.custom.css" rel="stylesheet" />	
		<script type="text/javascript" src="./public/jquery-1.4.2.min.js"></script>
		<script type="text/javascript" src="./public/jquery-ui-1.8.5.custom.min.js"></script>
		<link media="screen" href="./public/default.css" type="text/css" rel="stylesheet"/>
	</head>
	<body>
		<div id="content" class="center">
		<div id="auth">
		
		
<?php
if (!$auth) {
	if (isset($_POST['user']))
		$fuser = $_POST['user'];
	else if (isset($_GET['clientname']))
		$fuser = $_GET['clientname'];
	else
		$fuser = "";
	if (isset($_GET['url']))
		$redirect = $_GET['url'];
	else if (isset($_POST['redirect_to']))
		$redirect = $_POST['redirect_to'];
	else
		$redirect = "";
?>
	<h1><?=_("Authentication")?></h1>
	<form action="" method="POST" class="center">
		<input type="hidden" name="clientaddr" value="<?=$ip?>" />
		<input type="hidden" name="redirect_to" value="<?=$redirect?>"/>
		<table>
			<tr>
				<td class="label"><?=_("Username")?></td>
				<td class="entries"><input type="text" value="<?=$fuser?>" name="user" id="name"/></td>
			</tr>
			<tr>
				<td class="label"><?=_("Password")?></td>
				<td class="entries"><input type="password" value="" name="pass"/></td>
			</tr>
			<tr>
				<td class="label"></td>
				<td class="entries"><input class="submit" type="submit" value="<?=_("Login")?>" name="auth"/></td>
			</tr>
		</table>
<?php
	if (isset($error)) {
?>
		<p class="error"><?=$error?></p>
<?php
	}
?>
	</form>

<?php
} else {
?>
	<h1><?=_("Welcome")." ".$user?></h1>
	<p class="center"><?=_("You are authenticated with IP ") . " " . $auth[0]['ip'] . " " . _("since") . " " . date('Y/m/d H:i:s', $auth[0]['start_time'])?></p>
	<br /><br />
	<form action="" method="POST">
		<p class="center">
			<input class="submit" type="submit" value="<?=_("Logout")?>" name="unauth"/>
		</p>
	</form>
<?php

	if (in_array($user, $admin)) {
		if (isset($_POST['deco']) && isset($_POST['ip']) &&
		    !empty($_POST['ip'])) {
			sauthpf_unauth($_POST['ip'], 1);
		}
		$users = sauthpf_list_user();
?>
	<div id="list_users">
		<h1><?=_("Users actually connected")?></h1>
		<table>
			<tr><th><?=_("User")?></th><th><?=_("IP address")?></th><th><?=_("Connected on")?></th><th><?=_("Actions")?></th></tr>
<?php
		foreach ($users as $con) {
?>
			<tr><td><?=$con['user']?></td><td><?=$con['ip']?></td>
			    <td><?=date('Y/m/d H:i:s', $con['start_time'])?></td>
			    <td class="center"><form action="" method="POST">
			    <input type="hidden" name="ip" value="<?=$con['ip']?>"/>
			    <input type="submit" name="deco" value="<?=_("Force logout")?>"/>
			    </form></td></tr>
<?php
		}
?>
		</table>
	</div>
	<div id="historique">
		<h1><?=_("History")?></h1>
<?php
		if (isset($_POST['date']) && !empty($_POST['date'])) {
			$date = strtotime($_POST['date']);
		} else
			$date = time(NULL);
		if (!$date)
			$date = time(NULL);
		$date = $date;

?>
		<script type="text/javascript">
			$(function() {
				$("#datepicker").datepicker();
			});
		</script>
		<form action="" method="POST">
			<p>
			<?=_("Date")?> : <input id="datepicker" type="text" name="date" value="<?=date('Y/m/d', $date)?>"/>
			<input type="submit" value="<?=_("See")?>"/>
			</p>
		</form>
<?php
		$users = sauthpf_log_histo($date - 3600*24);
?>
		<table>
			<tr><th><?=_("Actions")?></th><th><?=_("User")?></th><th><?=_("IP address")?></th>
			    <th><?=_("Connected on")?></th><th><?=_("Date")?></th></tr>
<?php
		foreach($users as $con) {
?>
			<tr><td><?=($con['type']) ? _("Force logout") : _("Authentication") ?></td>
			    <td><?=$con['user']?></td><td><?=$con['ip']?></td>
			    <td><?=date('Y/m/d H:i:s', $con['start_time'])?></td>
			    <td><?=date('Y/m/d H:i:s', $con['event_time'])?></td></tr>
<?php
		}
?>
		</table>
	</div>
<?php

	}

}
?>
		</div>
<?php
if (isset($_GET['clientaddr'])) {
	$access['ip'] = $_GET['clientaddr'];
	$access['name'] = $_GET['clientname'];
	$access['user'] = $_GET['clientuser'];
	$access['group'] = $_GET['clientgroup'];
	$access['target'] = $_GET['targetgroup'];
	$access['url'] = $_GET['url'];

	if (!$access['name'])
		$access['name'] = _("Unknown");
	if (!$access['user'])
		$access['user'] = _("Not authenticated");
?>
	<div id="denied">
	<h1><?=_("Access denied")?> : </h1>
	<p>
		<span class="left"><?=_("Username")?> : </span>
		<span><?=$access['user']?></span>
	</p>
	<p>
		<span class="left"><?=_("Hostname")?> : </span>
		<span><?=$access['name']?></span>
	</p>
	<p>
		<span class="left"><?=_("IP address")?> : </span>
		<span><?=$access['ip']?></span>
	</p>
	<p>
		<span class="left"><?=_("Group")?> : </span>
		<span><?=$access['group']?></span>
	</p>
	<p>
		<span class="left"><?=_("Website category")?> : </span>
		<span><?=$access['target']?></span>
	</p>
	<p>
		<span class="left"><?=_("Website address")?> : </span>
		<span><?=$access['url']?></span>
	</p>
	</div>
<?php
}
?>
		</div>
		</div>
	</body>

</html>
