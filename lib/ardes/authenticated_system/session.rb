module Ardes#:nodoc:
  module AuthenticatedSystem
    # mixin for your Sessions controller
    module Session
      def self.included(base)
        base.send :attr_writer, :logged_in_message, :logged_out_message, :bad_credentials_message
      end
    
      def new
        # render login form
      end

      def create
        if params[:redirect_back]
          forget_location
          store_location_as_back_by_default
        end
      
        self.current_user = authenticated_system_model.authenticate(params[:email], params[:password])
      
        if logged_in?
          if params[:remember_me] == "1"
            current_user.remember_me
            cookies[:auth_token] = {:value => current_user.remember_token, :expires => current_user.remember_token_expires_at }
          end
          cookies[:recognition_token] = {:value => current_user.recognition_token , :expires => Time.now + 1.year}
          redirect_to_stored_location
          flash[:notice] = logged_in_message
      
        elsif (@user = authenticated_system_model.find_by_email(params[:email])) && !@user.activated?
          flash[:error] = not_activated_message
          render :action => 'request_activation'
      
        else
          flash[:error] = bad_credentials_message
          render :action => 'new'
        end
      end

      def destroy
        self.current_user.forget_me if logged_in?
        cookies.delete :auth_token
        if params[:unrecognize]
          cookies.delete :recognition_token 
        end
        reset_session
        flash[:notice] = logged_out_message
        redirect_to_stored_location
      end
    
    protected
      def logged_in_message
        @logged_in_message ||= "Logged in successfully"
      end
    
      def logged_out_message
        @logged_out_message ||= "You have been logged out."
      end
    
      def bad_credentials_message
        @bad_credentials_message ||= "Could not log you in with those details"
      end
    
      def not_activated_message
        @non_activated_message ||= "You need to activate your account - please check your email"
      end
    end
  end
end