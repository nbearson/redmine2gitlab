#!/usr/bin/env ruby
# from https://gist.github.com/jakimowicz/4079496

require 'faraday'
require 'json'
require 'gitlab'

module Redmine
  Host = ''
  APIKey = ''

  def self.connection
    raise 'must define a Host' if Host.nil?

    @connection ||= Faraday.new(:url => Host) do |faraday|
      # faraday.response  :logger
      faraday.adapter   Faraday.default_adapter
    end
  end

  def self.get(path, attrs = {})
    raise 'must define an APIKey' if APIKey.nil?
    result = connection.get(path, attrs) do |req|
      req.headers['X-Redmine-API-Key'] = APIKey
    end

    JSON.parse result.body
  end

  def self.post(path, attrs = {}, body = nil)
    raise 'must define an APIKey' if APIKey.nil?
    result = connection.post(path, attrs) do |req|
      req.body = body
      req.headers['Content-Type'] = 'application/json'
      req.headers['X-Redmine-API-Key'] = APIKey
    end

    JSON.parse result.body
  end

  def self.put(path, attrs = {}, body = nil)
    raise 'must define an APIKey' if APIKey.nil?
    result = connection.put(path, attrs) do |req|
      req.body = body
      req.headers['Content-Type'] = 'application/json'
      req.headers['X-Redmine-API-Key'] = APIKey
    end
  end

  class Base
    attr_accessor :id, :attributes

    def self.pluralized_resource_name
      @pluralized_resource_name ||= "#{self.resource_name}s"
    end

    def self.resource_name
      @resource_name ||= self.name.split('::').last.downcase
    end

    def self.list(options = {})
      list = Redmine.get "#{pluralized_resource_name}.json", options

      raise "did not find any #{pluralized_resource_name} in #{list.inspect}" if list[pluralized_resource_name].nil?

      list[pluralized_resource_name].collect do |attributes|
        obj = new
        obj.attributes = attributes
        obj
      end
    end

    def self.find(id)
      @find ||= {}
      return @find[id] if @find[id]

      response = Redmine.get "#{pluralized_resource_name}/#{id}.json"
      obj = new
      obj.attributes = response[resource_name]
      @find[id] = obj
    end

    def method_missing(sym)
      self.attributes[sym.to_s]
    end

    def id
      self.attributes['id']
    end
  end

  class Project < Base
    def issues(options = {})
      @issues ||= Issue.list(options.merge(:status_id => '*', :project_id => self.id, :limit => 999))
    end

    def categories
      @categories ||= IssueCategory.list :project_id => self.id
    end

    def category_by_name(name)
      @category_by_name ||= {}
      @category_by_name[name] ||= categories.detect { |category| category.name == name }
    end

    def self.by_identifier(identifier)
      self.list(:limit => 1000).detect { |project| project.identifier == identifier }
    end
  end

  class User < Base
    def self.by_email(email)
      @by_email ||= {}
      @by_email[email] ||= self.list.detect { |user| user.mail == email }
    end
  end

  class Issue < Base
    def self.create(project, subject, description, attributes = {})
      body = {
        :issue => {
          :project_id       => project.id,
          :subject          => subject,
          :description      => description,
          :tracker_id       => Tracker.first.id,
          :priority_id      => 4
        }.merge(attributes)
      }.to_json

      response = Redmine.post 'issues.json',  {}, body
    end

    def update(new_attributes = {})
      changes = {}
      new_attributes.each do |key, value|
        if key.match(/_id$/)
          if self.attributes[key.to_s.gsub(/_id$/, '')] and self.attributes[key.to_s.gsub(/_id$/, '')]['id'].to_s != value.to_s
            changes[key] = value
          end
        else
          changes[key] = value if self.attributes[key.to_s].to_s != value.to_s
        end
      end

      if changes.empty?
        puts 'no changes !'
        return
      end

      puts "changes: #{changes.inspect}"

      response = Redmine.put "issues/#{self.id}.json", {}, { :issue => changes }.to_json
    end

    def author
      Redmine::User.find self.attributes['author']['id']
    end

    def assignee
      Redmine::User.find self.attributes['assigned_to']['id'] rescue nil
    end
  end

  class IssueStatus < Base
    def self.pluralized_resource_name ; 'issue_statuses' ; end
    def self.resource_name ;            'issue_status' ; end

    def self.by_name(name)
      @by_name ||= {}
      @by_name[name] ||= list.detect { |status| status.name == name }
    end
  end

  class IssueCategory < Base
    def self.pluralized_resource_name ; 'issue_categories' ; end
    def self.resource_name ;            'issue_category' ; end

    def self.list(options = {})
      raise "must provide a project_id" if options[:project_id].nil?

      list = Redmine.get "projects/#{options.delete :project_id}/issue_categories.json", options

      raise "did not find any issue_categories in #{list.inspect}" if list['issue_categories'].nil?

      list['issue_categories'].collect do |attributes|
        obj = new
        obj.attributes = attributes
        obj
      end
    end
  end

  class Tracker < Base
    def self.first
      @first ||= self.list.first
    end
  end
end

Redmine::Host   = ''
Redmine::APIKey = ''

Gitlab.configure do |config|
  config.endpoint       = ''
  config.private_token  = ''
end

# puts Redmine::IssueStatus.list.inspect
# puts Redmine::IssueStatus.by_name('Assigned').inspect
# puts Redmine::Project.list.first.categories.inspect
# puts Redmine::Project.list.first.category_by_name('gitlab bug').inspect

# puts Redmine::Issue.create(Redmine::Project.list.first, 'testing creation from script', 'bleh', :assigned_to_id => 3, :status_id => Redmine::IssueStatus.by_name('Assigned').id, :category_id => Redmine::Project.list.first.category_by_name('gitlab task').id)

# TESTING ...
puts("writing gitlab project names")
Gitlab.projects.each do |gitlab_project|
  puts(gitlab_project.name)
end

#redmine_project = Redmine::Project.by_identifier("realearth")
#if redmine_project.nil? then
#  puts "redmine project name not good"
#else
#  puts "redmine project name IS GOOD!!!"
#end

#abort("exit early")

Gitlab.projects.each do |gitlab_project|
  next if not gitlab_project.name == 'YOUR-PROJECT-NAME'
  puts "iterating over project #{gitlab_project.name}"
  # First, find a project matching the gitlab one
  redmine_project = Redmine::Project.by_identifier("#{gitlab_project.path}")
  if redmine_project.nil? then
      puts "no redmine project #{gitlab_project.path} found"
      next
  end

  redmine_issues = redmine_project.issues

  gitlab_issues = Gitlab.issues(gitlab_project.id)
  processed_gitlab_issues = []

  puts "found #{gitlab_issues.count} issues on gitlab"

  # Then, iterate through all redmine issues of the project
  redmine_issues.each do |redmine_issue|
    puts "processing redmine issue #{redmine_issue.id} #{redmine_issue.subject}"

    # Find corresponding assignee in gitlab
    gitlab_assignee = Gitlab.users.detect { |u| u.email == redmine_issue.assignee.mail } unless redmine_issue.assignee.nil?
    gitlab_assignee_id = gitlab_assignee ? gitlab_assignee.id : nil
    puts "gitlab assignee: #{gitlab_assignee.inspect}"

    # Search for an existing issue
    existing_issue = gitlab_issues.detect { |gitlab_issue| gitlab_issue.title == redmine_issue.subject}

    puts "issue already existing on gitlab" if existing_issue

    if existing_issue   # Existing issue, updating status

      if Time.parse(existing_issue.updated_at) < Time.parse(redmine_issue.updated_on)
        puts "gitlab issue is older than redmine, updating gitlab issue"
        processed_gitlab_issues << existing_issue unless existing_issue.nil?
        Gitlab.edit_issue gitlab_project.id,
                          existing_issue.id,
                          :title => redmine_issue.subject,
                          :description => redmine_issue.description,
                          :assignee_id => gitlab_assignee_id,
                          :labels => redmine_issue.category['name'].gsub(/gitlab/, '').strip,
                          :closed => redmine_issue.status['name'] == 'Closed'
      else
        puts "gitlab issue is newer than redmine, skip the update"
      end

    else                # No existing issue, creating it

      puts "creating issue on gitlab"
      puts "issue: #{gitlab_project.id} #{redmine_issue.subject}"
      puts "description: #{redmine_issue.description}"
      puts "assignee: #{gitlab_assignee_id}"
#      puts "labels: #{redmine_issue.category['name'].gsub(/gitlab/, '').strip}"
      created_issue = Gitlab.create_issue gitlab_project.id,
                                          redmine_issue.subject,
                                          :description => redmine_issue.description,
                                          :assignee_id => gitlab_assignee_id
#                                          :labels => redmine_issue.category['name'].gsub(/gitlab/, '').strip

      processed_gitlab_issues << existing_issue unless existing_issue.nil?
    end

  end

  (gitlab_issues - processed_gitlab_issues).each do |gitlab_issue|
    puts "processing gitlab issue #{gitlab_issue.id} #{gitlab_issue.title}"

    # Find corresponding assignee in redmine
    redmine_assignee = Redmine::User.by_email(gitlab_issue.assignee.email) unless gitlab_issue.assignee.nil?
    redmine_assignee_id = redmine_assignee ? redmine_assignee.id : nil

    # Search for an existing issue
    existing_issue = redmine_issues.detect { |redmine_issue| gitlab_issue.title == redmine_issue.subject }

    puts "issue already existing on redmine" if existing_issue

    status = case
    when gitlab_issue.closed
      'Closed'
    when gitlab_issue.assignee
      'Assigned'
    else
      'New'
    end
    status_id = Redmine::IssueStatus.by_name(status).id

    if existing_issue   # Existing issue, updating status

      puts "updatig issue on redmine"
      existing_issue.update :description    => gitlab_issue.description,
                            :assigned_to_id => redmine_assignee_id,
                            :status_id      => status_id,
                            :done_ratio     => gitlab_issue.closed ? '100' : '0'

    else                # No existing issue, creating it
      puts "creating issue on redmine"
      Redmine::Issue.create(
        redmine_project,
        gitlab_issue.title,
        gitlab_issue.description,
        :assigned_to_id => redmine_assignee_id,
        :status_id      => status_id,
        :category_id    => Redmine::Project.list.first.category_by_name("gitlab").id,
        :done_ratio     => gitlab_issue.closed ? '100' : '0'
      )
    end

  end
end
