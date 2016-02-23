# Copyright (c) 2015-2016, Blockbridge Networks LLC.  All rights reserved.
# Use of this source code is governed by a BSD-style license, found
# in the LICENSE file.

module Helpers
  module Params
    def self.volume_sessions
      @@sessions ||= {}
    end

    def parse_params(params)
      return unless params[:Name] && params[:Name].include?('=')
      params[:Opts] ||= {}
      params[:Name].scan(/([^=,]+)=([^=,]+)/) do |key, val|
        params[:Opts][key.to_sym] = val
      end
      params[:Name] = params[:Opts].delete(:name) if params[:Opts].has_key? :name
    end

    def session_token_valid?(otp)
      return unless Params.volume_sessions[vol_name]
      return unless Params.volume_sessions[vol_name][:otp] == otp
      true
    end

    def get_session_token(otp)
      return unless session_token_valid?(otp)
      Params.volume_session[vol_name][:token]
    end

    def set_session_token(otp, token)
      Params.volume_sessions[vol_name] = {
        otp: otp,
        token: token,
      }
    end
  end
end
