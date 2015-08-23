<!--
TeamSpeak 3 Server Infoframe Template (EN)
Copyright 2009,2010 (c) TeamSpeak Systems GmbH
 
The replaceable variables are embedded in "%%" like %%SERVER_NAME%%. At this time you can also use 
%%?SERVER_NAME%% (note the questionmark), which is a tiny "if"- query. Use it, to remove the whole 
line, if a variable is empty or just "0".

Templates can be placed in "styles/" for default theme or in a sub folder named like an available 
theme (e.g. "styles/bluesky/"). Be aware that this template will not automaticly be translated when 
displayed.

-->

<style type="text/css">
@import url('Styles/Steam/style.css');
</style>

            <tr><td>&nbsp;</td></tr>

<table id="header">
	<tr><td class="header"><table>
			<tr><td>%%SERVER_NAME%%</td></tr>
    </table></td></tr>
	<tr><td><table>
		<tr><td class="headersub">
		<a class="refresh" href="%%?SERVER_REFRESH_INACTIVE%%">Refresh Information</a>
		<a class="refresh" href="%%?SERVER_REFRESH_ACTIVE%%">Refresh Information</a>
		</td></tr>			
    </table></td></tr>
</table>

<tr><td>&nbsp;</td></tr>
        
<table id="container">
	<td><table id="info">    
		<tr><td class="user"><table>
			<tr><td class="infoheader">SERVER INFO</td></tr> 
			<tr>
				<td class="infotext">Server Adress:</td>
				<td class="infotext">%%SERVER_ADDRESS%%:%%SERVER_PORT%%</td>
			</tr>
			<tr>    
				<td class="infotext">Version:</td>
				<td class="infotext">%%SERVER_VERSION%% on %%SERVER_PLATFORM%%</td>
			</tr>
			<tr><td class="infotext">Online since:</td><td class="infotext">%%SERVER_UPTIME%%</td></tr>
			<tr><td class="infotext">Client connections:</td><td class="infotext">[%%SERVER_CLIENTS_ONLINE%%] / [%%SERVER_CLIENT_CONNECTIONS%%] </td></tr>
			<tr><td class="infotext">Query connections:</td><td class="infotext">[%%SERVER_QUERYCLIENTS_ONLINE%%] / [%%SERVER_QUERY_CLIENT_CONNECTIONS%%]</td></tr>
			<tr><td class="infotext">Channel & Max Slots:</td><td class="infotext">[%%SERVER_CHANNELS_ONLINE%%] / [%%SERVER_MAXCLIENTS%%]</td></tr>                 	
		</table></td></tr>
		<tr><td>&nbsp;</td></tr>
	</table></td>
</table>    

