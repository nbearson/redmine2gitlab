# https://gist.github.com/jakimowicz/4079496

FROM ruby:latest
RUN gem install faraday
RUN gem install gitlab

