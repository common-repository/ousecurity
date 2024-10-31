<?php
/*
Plugin Name: OU Security
Plugin URI: http://oleksandrustymenko.com/ousecurity
Description: The plugin, which protects the site from malicious scripts, also blocks the scanner to access wp-content folder.
Version: 1.0
Author: Oleksandr Ustymenko
Author URI: http://oleksandrustymenko.com
*/

/*  
	Copyright 2016 oleksandr87 (email:ustymenkooleksandrnew@gmail.com)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

global $jal_db_version;
$jal_db_version = "1.0";

function ousecurityactivate () 
{
	global $wpdb;
	global $jal_db_version;
	
	$ousecuritydbtable = $wpdb->prefix . "ousecuritydb";
	if($wpdb->get_var("show tables like '$ousecuritydbtable'") != $ousecuritydbtable)
	{     
        $sql = "CREATE TABLE " . $ousecuritydbtable . " (
		ousecurity_id INTEGER NOT NULL AUTO_INCREMENT,
		ousecurity_id_user INTEGER,
		ousecurity_status TEXT,
		UNIQUE KEY  (ousecurity_id));"; 
	  
		require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
		dbDelta($sql);
		add_option("jal_db_version", $jal_db_version);  
        
    }
}
register_activation_hook(__FILE__,'ousecurityactivate');

function ousecuritydeactivate()
{
	global $wpdb;
	$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}ousecuritydb");
}
register_uninstall_hook(__FILE__, 'ousecuritydeactivate');

add_action('admin_menu', 'ou_security_option_pages');

function ou_security_option_pages() 
{
	add_options_page( 'OU Security', 'OU Security', 'manage_options', 'ou_security_option', 'ou_security_option_function');
}

function ou_security_option_function()
{
    $ou_htaccess = get_home_path().".htaccess";
    $ou_code2 = 'IndexIgnore *.css *.php *.js .htaccess'.PHP_EOL; 
    $ou_code4_1 = '<files wp-config.php>'.PHP_EOL;
    $ou_code4_2 = 'order allow,deny'.PHP_EOL;
    $ou_code4_3 = 'deny from all'.PHP_EOL;
    $ou_code4_4 = '</files>'.PHP_EOL;
    $ou_code5_1 = '<files ~ "^.*\.([Hh][Tt][Aa])">'.PHP_EOL;
    $ou_code5_2 = 'order allow,deny'.PHP_EOL;
    $ou_code5_3 = 'deny from all'.PHP_EOL;
    $ou_code5_4 = 'satisfy all'.PHP_EOL;
    $ou_code5_5 = '</files>'.PHP_EOL;
    
    $ou_code = $ou_code2.$ou_code4_1.$ou_code4_2.$ou_code4_3.$ou_code4_4.$ou_code5_1.$ou_code5_2.$ou_code5_3.$ou_code5_4.$ou_code5_5;
    
    
    global $wpdb;
    $ou_securitycheck_user = get_current_user_id();
    $ousecuritydbtable1 = $wpdb->prefix . "ousecuritydb";  
    if(!empty($ou_securitycheck_user))
    {
        $ou_check_security_db =	$wpdb->get_var( "SELECT COUNT(*) FROM $ousecuritydbtable1 where ousecurity_id = 1 AND ousecurity_id_user = $ou_securitycheck_user" );
            
        if($ou_check_security_db ==0)
        {
            $ou_security_status ='yes';
            $wpdb->insert( $ousecuritydbtable1, array( 'ousecurity_status' => $ou_security_status, 'ousecurity_id_user' => $ou_securitycheck_user  ) );
            //file_put_contents($ou_htaccess, $ou_code, FILE_APPEND);
            
            insert_with_markers($ou_htaccess, 'OU Security', $ou_code);
        }
    }
    
    if(file_exists($ou_htaccess))
    {   
        echo '<div style="margin:10px; width:460px;">';
            echo '<div style="width:450px; background:#660000;">';
                echo '<div style="padding:5px; font-size:18px; text-align:left; color:#E8E8E8;">';
				    echo '<b>OU Security</b>';
			     echo '</div>';
            echo '</div>';
            echo '<div style="width:448px; overflow:hidden; min-height:60px; border:1px solid #660000;">';       
                echo '<table style="color: #ffffff; border-collapse: collapse; background:#4d0000; width:448px;">';
                    echo '<tr>';
                        echo '<td style="border: 1px solid #808080; padding:2px 5px 2px 5px; ">';
                            echo 'Directory browsing';
                        echo '</td>';
                        echo '<td style="border: 1px solid #808080; padding:2px 5px 2px 5px; ">';
                            echo 'Disabled';
                        echo '</td>';
                    echo '</tr>';
                    echo '<tr>';
                        echo '<td style="border: 1px solid #808080; padding:2px 5px 2px 5px; ">';
                            echo 'Protect wp-config.php';
                        echo '</td>';
                        echo '<td style="border: 1px solid #808080; padding:2px 5px 2px 5px; ">';
                            echo 'Enabled';
                        echo '</td>';
                    echo '</tr>';
                    echo '<tr>';
                        echo '<td style="border: 1px solid #808080; padding:2px 5px 2px 5px; ">';
                            echo 'Protect .htaccess';
                        echo '</td>';
                        echo '<td style="border: 1px solid #808080; padding:2px 5px 2px 5px; ">';
                            echo 'Enabled';
                        echo '</td>';
                    echo '</tr>';
                echo '</table>';
            echo '</div>';
        echo '</div>';
        
    } 
}
?>