<?php
require_once 'config/session.php';

logout();
header('Location: login.php');
exit();

