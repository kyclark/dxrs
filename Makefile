RUN = cargo run --quiet --

desc-analysis:
	$(RUN) desc analysis-GFfkqz0054JJG8p1GBpv7qGX

desc-job:
	#$(RUN) desc job-GFfkqz0054JJG8p1GBpv7qGb
	$(RUN) desc job-GZykQKj0GYJfQj2Q4xqKV5j0

desc-file:
	$(RUN) desc file-GFfbj0Q054J4ypqJ8vQjF4V7

desc-app:
	$(RUN) desc app-GJzjbP00vyjyXPpkFv7bxf1F

desc-applet:
	$(RUN) desc applet-GZ2BF8Q0jZ5qj3bQBX5BFjjZ

desc-db:
	$(RUN) desc database-GZ6vP1801xf4fXjB3YVX011f

desc-record:
	$(RUN) desc record-GZ6vQPj0b5pJfbQ3XffQB1BJ

desc-project:
	$(RUN) desc project-GYgj4800jZ5YqgZ24ZzJpZvq

desc-container:
	$(RUN) desc container-GJzjbP008QGyXPpkFv7bxf1G

all: desc-analysis desc-job desc-file desc-app desc-applet desc-db desc-record desc-project desc-container
