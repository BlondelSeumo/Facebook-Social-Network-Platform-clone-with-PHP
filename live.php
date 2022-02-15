<?php

/**
 * live
 * 
 * @package Sngine
 * @author Zamblek
 */

// fetch bootloader
require('bootloader.php');

// live enabled
if (!$system['live_enabled']) {
	_error(404);
}

// live permission
if (!$user->_data['can_go_live']) {
	_error('PERMISSION');
}

// check demo account
if ($user->_data['user_demo']) {
	_error('PERMISSION');
}

// page header
page_header($system['system_title'] . ' - ' . __("Live Video"));

// get agora (uid|token|channel_name)
$agora = $user->agora_token_builder(true);
/* assign variables */
$smarty->assign('agora', $agora);

// page footer
page_footer("live");
