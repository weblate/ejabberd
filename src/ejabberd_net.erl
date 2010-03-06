%%%----------------------------------------------------------------------
%%% File    : ejabberd_net.erl
%%% Author  : Mikael Magnusson <mikma@users.sourceforge.net>
%%% Purpose : Serve C2S connection
%%% Created : 6 June 2007 by Mikael Magnusson <mikma@users.sourceforge.net>
%%% Id      : $Id: $
%%%----------------------------------------------------------------------

-module(ejabberd_net).
-author('mikma@users.sourceforge.net').
%% -update_info({update, 0}).

-export([gethostname/1]).

-include("ejabberd.hrl").
-include_lib("kernel/include/inet.hrl").

%% Copied from ejabberd_socket.erl of ejabberd 2.0.3
-record(socket_state, {sockmod, socket, receiver}).

%%
%% gethostname(Socket)
%%
gethostname(Socket) ->
    ?INFO_MSG("gethostname ~p~n", [Socket]),
%%     {ok, "skinner.hem.za.org"}.

    case ejabberd_config:get_local_option({sasl_fqdn, ?MYNAME}) of
      undefined ->
        {ok, {Addr, _Port}} = inet:sockname(Socket#socket_state.socket),
        case inet:gethostbyaddr(Addr) of
            {ok, HostEnt} when is_record(HostEnt, hostent) ->
                {ok, HostEnt#hostent.h_name};
	    {error, nxdomain} ->
		    % Quick fix
		    {ok, inet_parse:ntoa(Addr)};
            {error, What} ->
                ?ERROR_MSG("Error in gethostname:~nSocket: ~p~nError: ~p at Addr ~p", [Socket, What, Addr]),
                error
        end;
      F -> {ok, F}
    end.
