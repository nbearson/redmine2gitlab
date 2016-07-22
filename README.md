# redmine2gitlab

```bash
docker build -t redmine2gitlab .
docker run -it --rm -v "$PWD":/redmine2gitlab -w /redmine2gitlab redmine2gitlab /bin/bash
```

## To use, edit the following:
edit the following

```ruby
Redmine::Host   = ''
Redmine::APIKey = ''
```

```ruby
Gitlab.configure do |config|
  config.endpoint       = ''
  config.private_token  = ''
end
```

```ruby
  next if not gitlab_project.name == 'YOUR-PROJECT-NAME'
```
