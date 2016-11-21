class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception

  def hello
    render html: "<h1>Hello World!</h1>"
  end
end
