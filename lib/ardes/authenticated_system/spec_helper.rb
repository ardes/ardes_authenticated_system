module Ardes
  module AuthenticatedSystem
    module SpecHelper
      # Sets the current user in the session
      def not_logged_in
        controller.send(:current_user=, :false)
      end

      def logged_in_as(user)
        controller.send(:current_user=, user)
      end
    
      def recognized_as(user)
        controller.stub!(:recognized_user).and_return(user)
      end
    
      # Sets HTTP auth as specified email, and password
      def authorize_as(email, password)
        @request.env["HTTP_AUTHORIZATION"] = "Basic #{Base64.encode64("#{email}:#{password}")}"
      end
    end
  end
end