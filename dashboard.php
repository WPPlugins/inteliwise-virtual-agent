<?php
/**
 * getDashBoard
 */

$url 		= get_bloginfo('url');
$plugin_url = $url .'/wp-content/plugins/inteliwise/';
$row = $api->getDashBoard();

$html = $api->getDashBoardHtml();

?>


<div class="wrap">
	<div class="icon32" id="icon-link-manager"><br></div>
	<h2>Statistics</h2>

        <div class="metabox-holder" id="poststuff">
			<div  class="postbox-container" >
			<div id="post-body-content" >
				<div class="stuffbox" id="namediv">
				<h3>Dashboard</h3>
                                    <div class="inside">

                                        <?php echo $html;?>

					</div>
				</div>
			</div>
		</div>
	</div>
</div>
