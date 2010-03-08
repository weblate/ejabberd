%%%----------------------------------------------------------------------
%%% File    : cyrsasl_gssapi.erl
%%% Author  : Mikael Magnusson <mikma@users.sourceforge.net>
%%% Purpose : GSSAPI SASL mechanism
%%% Created : 1 June 2007 by Mikael Magnusson <mikma@users.sourceforge.net>
%%% Id      : $Id: $
%%%----------------------------------------------------------------------
%%%
%%% Copyright (C) 2007  Mikael Magnusson <mikma@users.sourceforge.net>
%%%
%%% Permission is hereby granted, free of charge, to any person
%%% obtaining a copy of this software and associated documentation
%%% files (the "Software"), to deal in the Software without
%%% restriction, including without limitation the rights to use, copy,
%%% modify, merge, publish, distribute, sublicense, and/or sell copies
%%% of the Software, and to permit persons to whom the Software is
%%% furnished to do so, subject to the following conditions:
%%%
%%% The above copyright notice and this permission notice shall be
%%% included in all copies or substantial portions of the Software.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
%%% EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
%%% MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
%%% NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
%%% BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
%%% ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
%%% CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
%%% SOFTWARE.
%%%

%%%
%%% configuration options:
%%% {sasl_realm, "<Kerberos realm>"}.
%%%
%%% environment variables:
%%% KRB5_KTNAME
%%%

-module(cyrsasl_gssapi).
-author('mikma@users.sourceforge.net').
-vsn('$Revision: $ ').

-include("ejabberd.hrl").

-export([start/1,
	 stop/0,
	 mech_new/1,
	 mech_step/2]).

-behaviour(cyrsasl).

-define(SERVER, cyrsasl_gssapi).

-record(state, {sasl,
		needsmore=true,
		step=0,
		host,
		authid,
		authzid,
		authrealm}).

start(_Opts) ->
    ChildSpec =
	{?SERVER,
	 {esasl, start_link, [{local, ?SERVER}]},
	 transient,
	 1000,
	 worker,
	 [esasl]},

    {ok, _Pid} = supervisor:start_child(ejabberd_sup, ChildSpec),

    cyrsasl:register_mechanism("GSSAPI", ?MODULE, false).

stop() ->
    esasl:stop(?SERVER),
    supervisor:terminate_child(ejabberd_sup, ?SERVER),
    supervisor:delete_child(ejabberd_sup, ?SERVER).

mech_new(#sasl_ctx{host=Host, fqdn=FQDN}) ->
    ?DEBUG("mech_new ~p ~p~n", [Host, FQDN]),
    {ok, Sasl} = esasl:server_start(?SERVER, "GSSAPI", "xmpp", FQDN),
    {ok, #state{sasl=Sasl,host=Host}}.

mech_step(State, ClientIn) when is_list(ClientIn) ->
    catch do_step(State, ClientIn).

do_step(#state{needsmore=false}=State, _) ->
    check_user(State);
do_step(#state{needsmore=true,sasl=Sasl,step=Step}=State, ClientIn) ->
    ?DEBUG("mech_step~n", []),
    case esasl:step(Sasl, list_to_binary(ClientIn)) of
	{ok, RspAuth} ->
	    ?DEBUG("ok~n", []),
	    {ok, Display_name} = esasl:property_get(Sasl, gssapi_display_name),
	    {ok, Authzid} = esasl:property_get(Sasl, authzid),
	    {Authid, [$@ | Auth_realm]} =
		lists:splitwith(fun(E)->E =/= $@ end, Display_name),
	    State1 = State#state{authid=Authid,
				 authzid=Authzid,
				 authrealm=Auth_realm},
	    handle_step_ok(State1, binary_to_list(RspAuth));
	{needsmore, RspAuth} ->
	    ?DEBUG("needsmore~n", []),
	    if (Step > 0) and (ClientIn =:= []) and (RspAuth =:= <<>>) ->
		    {error, "not-authorized"};
		true ->
		    {continue, binary_to_list(RspAuth),
		     State#state{step=Step+1}}
	    end;
	{error, _} ->
	    {error, "not-authorized"}
    end.

handle_step_ok(State, []) ->
    check_user(State);
handle_step_ok(#state{step=Step}=State, RspAuth) ->
    ?DEBUG("continue~n", []),
    {continue, RspAuth, State#state{needsmore=false,step=Step+1}}.

check_user(#state{authid=Authid,authzid=Authzid,
		  authrealm=Auth_realm,host=Host}) ->
    Realm = ejabberd_config:get_local_option({sasl_realm, Host}),

    if Realm =/= Auth_realm ->
	    ?DEBUG("bad realm ~p (expected ~p)~n",[Auth_realm, Realm]),
	    throw({error, "not-authorized"});
       true ->
	    ok
    end,

    case ejabberd_auth:is_user_exists(Authid, Host) of
	false ->
	    ?DEBUG("bad user ~p~n",[Authid]),
	    throw({error, "not-authorized"});
	true ->
	    ok
    end,

    ?DEBUG("GSSAPI authenticated ~p ~p~n", [Authid, Authzid]),
    {ok, [{username, Authid}, {authzid, Authzid}]}.
