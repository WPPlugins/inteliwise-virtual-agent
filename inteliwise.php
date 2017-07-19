<?php
/**
 * Plugin Name: InteliWISE Virtual Agent
 * Plugin URI: http://inteliwise.com/wordpress
 * Description: Improve lead conversion from your Contact form and give your Feedback a new look with the #1 Virtual Agent WordPress plugin. <a href="https://panel.inteliwise.com/index.php?view=plugin&task=wordpress">Signup for free 30-day trial</a>
 * Author: InteliWISE
 * Author URI: http://inteliwise.com/
 * Version: 1.0.3
 */
require_once ('IW_SAAS_Client.class.php');

class Client {

    var $client;

    function __construct($developerCode, $login, $password) {
        $this->client = new IW_SAAS_Client($developerCode, 'api.inteliwise.com');
        $retCode = $this->client->session->authenticateAndSelectInstallation(array('login' => $login, 'password' => $password));

        if ($retCode == IW_SAAS_Client::RESULT_CODE_OK) {
            return true;
        } else {
            throw new Exception($retCode);
        }
    }

    function getLayoutModes() {
        $err = $this->client->character->getLayoutModes(null, & $layout_modes);
        if ($retCode == IW_SAAS_Client::RESULT_CODE_OK) {
            return $layout_modes;
        } else {
            throw new Exception($retCode);
        }
    }

    function getPluginVersions() {
        $retCode = $this->client->session->getPluginVersions(null, & $versions);
        if ($retCode == IW_SAAS_Client::RESULT_CODE_OK) {
            foreach ($versions as $version)
                if ($version->name == 'wordPress')
                    return $version->version;
        }
        else {
            throw new Exception($retCode);
        }
    }

    function getDashBoardHtml() {
        $retCode = $this->client->statistics->getDashBoardHtml(array('_newVersion_' => true), & $dashboard);

        if ($retCode == IW_SAAS_Client::RESULT_CODE_OK) {
            return $dashboard;
        } else {
            throw new Exception($retCode);
        }
    }

    function getDashBoard() {
        // $retCode = $this->client->statistics->getDashBoard(null,&$dashboard);
        $retCode = $this->client->statistics->getDashBoard(array('_newVersion_' => true), & $dashboard);

        if ($retCode == IW_SAAS_Client::RESULT_CODE_OK) {
            return $dashboard;
        } else {
            throw new Exception($retCode);
        }
    }

    function getCode($layoutMode) {

        $retCode = $this->client->character->getCode(array('layoutMode' => (string) $layoutMode), & $embed_code);
        if ($retCode == IW_SAAS_Client::RESULT_CODE_OK) {
            return $embed_code->code;
        } else {
            throw new Exception($retCode);
        }
    }

}

register_deactivation_hook(__FILE__, 'IW_SAAS_remove');

function IW_SAAS_remove() {
    delete_option('IW_SAAS_DeveloperCode');
    delete_option('IW_SAAS_Password');
    delete_option('IW_SAAS_Login');
    delete_option('IW_SAAS_Version');
    delete_option('IW_SAAS_LayoutMode');
}

function IW_SAAS_admin_menu() {
    add_options_page('InteliWISE Virtual Agent', 'InteliWISE Virtual Agent Settings', 'administrator', 'IW_SAAS', 'IW_SAAS_plugin_page');
    add_action('admin_init', 'IW_SAAS_settings');
}

function IW_SAAS_settings() {


    register_setting('IW_SAAS_settings_group', 'IW_SAAS_Password');
    register_setting('IW_SAAS_settings_group', 'IW_SAAS_Login');
    register_setting('IW_SAAS_settings_group', 'IW_SAAS_Version');
    register_setting('IW_SAAS_settings_group', 'IW_SAAS_LayoutMode');

    add_option('IW_SAAS_DeveloperCode', '44269b2984cb2416534dd2126122486c908b4481a069a4cb0c3453290451134e', '', 'yes');
}

if (is_admin ()) {
    add_action('admin_menu', 'IW_SAAS_admin_menu');
}

function IW_disable_admin_avatar()
{
	remove_action('shutdown', 'IW_embed');
}

add_action('admin_init', 'IW_disable_admin_avatar');
add_action('shutdown', 'IW_embed');

function IW_embed()
{
    try {
        $api = new Client(get_option('IW_SAAS_DeveloperCode'), get_option('IW_SAAS_Login'), get_option('IW_SAAS_Password'));
        echo $api->getCode(get_option('IW_SAAS_LayoutMode'));
    } catch (Exception $e) {
//        echo 'Caught exception: ', $e->getMessage(), "\n";
        echo 'Your virtual agent is not configured properly. Please configure it in the "Settings" panel';
    }
}
function IW_SAAS_plugin_page() {
?>


	<div class="wrap">
		<div id="icon-options-general" class="icon32"><br /></div>
		<h2>InteliWISE Virtual Agent Options</h2>
		<form method="post" action="options.php"><?php settings_fields('IW_SAAS_settings_group'); ?>

			<input type="hidden" name="action" value="update" />
			<input type="hidden" name="page_options" value="IW_SAAS_Password" />
			<input type="hidden" name="page_options" value="IW_SAAS_Login" />
			<input type="hidden" name="page_options" value="IW_SAAS_LayoutMode" />

			<div class="metabox-holder" id="poststuff">
				<div id="post-body">
					<div id="post-body-content">
						<div class="stuffbox" id="namediv">
							<h3>Useful links</h3>
							<div class="inside">
								<ul>
									<li><strong><a href="http://support.inteliwise.com/">Customer Support</a></strong></li>
									<li><strong><a href="http://www.youtube.com/watch?v=9aOb6bnYH8k&feature=channel_video_title">How to Configure Your Widget</a></strong></li>
									<li><strong><a href="http://inteliwise.com/wordpress">Marketing Examples</a></strong></li>
									<li><!-- BEGIN LivePerson Button Code --><span id="lpButDivID-1315233771287"></span><script type="text/javascript" charset="UTF-8" src="https://server.iad.liveperson.net/hc/68769754/?cmd=mTagRepstate&site=68769754&buttonID=7&divID=lpButDivID-1315233771287&bt=3&c=1"></script><!-- END LivePerson Button code --></li>
								</ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="metabox-holder" id="poststuff">
                <div id="post-body">
                    <div id="post-body-content">
                        <div class="stuffbox" id="namediv">
                            <h3>Login</h3>
                            <div class="inside">
                                <table class="form-table">
                                    <tr valign="top">
                                        <th scope="row">login:</th>
                                        <td><input name="IW_SAAS_Login" type="text" id="IW_SAAS_Login" value="<?php echo get_option('IW_SAAS_Login'); ?>" /> <span class="description"></span></td>
                                    </tr>
                                    <tr valign="top">
                                        <th scope="row">password:</th>
                                        <td><input name="IW_SAAS_Password" type="password" id="IW_SAAS_Password" value="<?php echo get_option('IW_SAAS_Password'); ?>" /> <span class="description"></span></td>
                                    </tr>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <p><input type="submit" value="<?php _e('Save Changes') ?>" /></p>

<?php
    try {
        $api = new Client(get_option('IW_SAAS_DeveloperCode'), get_option('IW_SAAS_Login'), get_option('IW_SAAS_Password'));
?>

			<div class="metabox-holder" id="poststuff">
				<div id="post-body">
					<div id="post-body-content">
						<div class="stuffbox" id="namediv">
							<h3>Settings</h3>
							<div class="inside">
								<table class="form-table">
									<tr>
										<td>plugin version:</td>
										<td><?php echo $api->getPluginVersions(); ?></td>
									</tr>
									<tr>
										<th scope="row"><label for="IW_SAAS_LayoutMode">layout mode:</label></th>
										<td><select id="IW_SAAS_LayoutMode" name="IW_SAAS_LayoutMode">
<?php foreach ($api->getLayoutModes() as $mode): ?>
												<option value="<?php echo $mode->id; ?>"
<?php if ($mode->id == get_option('IW_SAAS_LayoutMode')): ?>
                                                            selected="selected" <?php endif; ?>><?php echo $mode->name; ?></option>
<?php endforeach; ?>
										</select></td>
									</tr>
								</table>
							</div>
						</div>
					</div>
				</div>
			</div>
			<p><input type="submit" value="<?php _e('Save Changes') ?>" /></p>


			<?php include_once 'dashboard.php'; ?>
		</form>

<?php
            } catch (Exception $e) {
                //	 echo 'Caught exception: ',  $e->getMessage(), "\n";
                echo '<strong><a style="color:red" href="https://panel.inteliwise.com/index.php?view=plugin&task=wordpress">Register for a Free Trial Account</a></strong>';
            }
?>

	</div>
<!-- BEGIN LivePerson Monitor. --><script language='javascript'> var lpMTagConfig = {'lpServer' : "server.iad.liveperson.net",'lpNumber' : "68769754",'lpProtocol' : (document.location.toString().indexOf('https:')==0) ? 'https' : 'http'}; function lpAddMonitorTag(src){if(typeof(src)=='undefined'||typeof(src)=='object'){src=lpMTagConfig.lpMTagSrc?lpMTagConfig.lpMTagSrc:'/hcp/html/mTag.js';}if(src.indexOf('http')!=0){src=lpMTagConfig.lpProtocol+"://"+lpMTagConfig.lpServer+src+'?site='+lpMTagConfig.lpNumber;}else{if(src.indexOf('site=')<0){if(src.indexOf('?')<0)src=src+'?';else src=src+'&';src=src+'site='+lpMTagConfig.lpNumber;}};var s=document.createElement('script');s.setAttribute('type','text/javascript');s.setAttribute('charset','iso-8859-1');s.setAttribute('src',src);document.getElementsByTagName('head').item(0).appendChild(s);} if (window.attachEvent) window.attachEvent('onload',lpAddMonitorTag); else window.addEventListener("load",lpAddMonitorTag,false);</script><!-- END LivePerson Monitor. -->
<?php } ?>