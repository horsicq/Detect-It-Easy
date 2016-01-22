<!--
Predefined values have to be inside the html comment-tag to make sure that they will be parsed
before the replacing begins! Remove the "#" to enable.

%%IMAGES_MAX_WIDTH%%256
%%IMAGES_MAX_HEIGHT%%256
-->

<style type="text/css">
@import url('Styles/Steam/style.css');
</style>

<tr><td>&nbsp;</td></tr>

<table id="header">
	<tr><td class="header"><table>
		<tr><td>%%CHANNEL_NAME%%</td></tr>
    </table></td></tr>
	<tr><td class="headersub">%%?CHANNEL_TOPIC%%</td></tr>
</table>
</table>
        
<table id="container">
	<td><table id="info">    
		<tr><td class="user"><table>
			<tr><td class="infoheader">CHANNEL INFO</td></tr> 
			<tr>
				<td class="infotext">Sound Codec:</td>
				<td class="infotext">%%CHANNEL_CODEC%%</td>
			</tr>
			<tr>    
				<td class="infotext">Codec Quality:</td>
				<td class="infotext">%%CHANNEL_CODEC_QUALITY%% - Estimated bitrate (%%CHANNEL_CODEC_BITRATE%%/s)</td>
			</tr>
			<tr><td class="infotext">Channel Type:</td><td class="infotext">%%?CHANNEL_FLAGS%%</td></tr>
			<tr><td class="infotext">Channel ID:</td><td class="infotext">%%CHANNEL_ID%%</td></tr>
			<tr><td class="infotext">Current Clients:</td><td class="infotext">%%?CHANNEL_CLIENTS_COUNT%% / %%CHANNEL_FLAG_MAXCLIENTS%%</td></tr>
			<tr><td class="infotext">Needed Talk Power:</td><td class="infotext">%%?CHANNEL_NEEDED_TALK_POWER%%</td></tr>
			<tr><td class="infotext">Subscription Status:</td><td class="infotext">%%CHANNEL_SUBSCRIPTION%%</td></tr>   
			<tr><td class="infotext">Voice Encryption:</td><td class="infotext">%%CHANNEL_VOICE_DATA_ENCRYPTED%%</td></tr>                           	
		</table></td></tr>
	<tr><td>&nbsp;</td></tr>
	<tr><td class="scanner"><table><tr><td class="infoheader">CHANNEL DESCRIPTION</td><tr><td class="infotext">%%?CHANNEL_DESCRIPTION%%</td></tr></table></td></tr>        
</table></td></tr>
        



