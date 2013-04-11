from fabric.api import local
import os
from time import sleep

from fabric.api import task, settings, sudo,run, execute, env, parallel, cd, lcd
from fabric.contrib.files import upload_template, put
from fabric.colors import *
from boto.ec2 import EC2Connection, get_region, connect_to_region

import configuration as config

type = 'all'
count = 0
filter = {'instance-state-name' : 'running','tag:project' : config.PROJECT,'tag:type' : 'locust'}
remote_folder = "/home/ubuntu/"

def master():
    global type
    global count
    global filter
    type = 'master'
    count = 1
    filter.update({ 'tag:sub_type' : type})
    _set_env()

def slave():
    global type
    global count
    global filter
    type = 'slave'
    count = config.SLAVE_COUNT
    filter.update({ 'tag:sub_type' : type})
    _set_env()

def all():
    _set_env()   

@parallel
def start():
  """ start the processes
  """
  master_filter = dict(filter.items() + { 'tag:sub_type' : 'master'}.items())
  ec2_connection = _get_ec2_connection()
  search = ec2_connection.get_all_instances(filters=master_filter) 
  master_public_url = ''
  for reservation in search:
    for instance in reservation.instances:
      master_public_url = instance.public_dns_name
  remote_file_location = remote_folder + config.LOCAL_LOCUST_FILE
  if env.host_string == master_public_url:
      run('screen -d -m bash -c "locust -f {0} -H {1} --ramp --master"'.format(remote_file_location, config.TARGET_DOMAIN), pty=False)
  else:
      run('screen -d -m bash -c "locust -f {0} -H {1} --slave --ramp --master-host={2}"'.format(remote_file_location, config.TARGET_DOMAIN, master_public_url), pty=False)
  print(green("website url: http://{0}:8089".format(master_public_url)))

def list():
  print(green(env.host_string))

def url():
  print(green("website url: http://{0}:8089".format(env.host_string)))

@parallel
def stop():
  sudo('killall -9 screen')

@parallel
def configure():
    """ Configures packages on the virtual OS.

    """
    sudo('apt-get update -q')
    sudo('apt-get install -q build-essential python-pip python-dev libevent-dev libzmq-dev --assume-yes')
    sudo('pip install  -q locustio  gevent-zeromq')
    sudo('pip install -Iv -q pyzmq==2.2.0.1')
    upload_directory()
    if config.REQUIREMENTS_FILE != '':  
          with cd(remote_folder):
              sudo('pip install --upgrade -q -r '+ config.REQUIREMENTS_FILE)


def create():    
  global type
  if type == "all":
      master()
      create()
      slave()
      create()
      type = "all"
  else:
      ec2_connection = _get_ec2_connection()
      reservation = ec2_connection.run_instances(config.AMI_ID, key_name=config.AWS_KEY_FILE,instance_type=config.AWS_INSTANCE_SIZE,
      security_group_ids=config.AMI_SECURITY_GROUPS,min_count=count, max_count=count)
      
      print(reservation.instances)
      for instance in reservation.instances:
        print(instance)
        print('creating a new instance')
        sleep(10)

        instance.update()

        while instance.state != 'running':
            sleep(10)
            print('sleep')
            instance.update()

        print('tagging instance {0} as a {1}'.format(instance.id, type))
        instance.add_tag("project",config.PROJECT)
        instance.add_tag("type","locust")
        instance.add_tag("sub_type", type)

def terminate():
    """ Terminates all instances with the current
    """
    ec2_connection = _get_ec2_connection()

    print('Connected to {0}'.format(ec2_connection))

    
    if len(env.hosts) == 0:
        print('no existing {0}'.format(type))
    else:
        search = ec2_connection.get_all_instances(filters=filter) 
        
        for reservation in search:
          print('found {0} {1}'.format(len(reservation.instances),type))
          for instance in reservation.instances:
            print('Terminating instance {0}'.format(instance.id))
            ec2_connection.terminate_instances([instance.id])

@parallel
def upload_directory():
    """ puts files on all servers
    """
    global remote_folder
    sudo('mkdir -p {0}'.format(remote_folder))
    with lcd(config.LOCAL_DIRECTORY):
      put("*", remote_folder,True)

def _set_env():
    ec2_connection = _get_ec2_connection()
    print('Connected to {0}'.format(ec2_connection))

    search = ec2_connection.get_all_instances(filters=filter) 
    
    for result in search:
      env.hosts = env.hosts + map(_get_instance_url, result.instances)
      
    env.key_filename = config.LOCAL_AWS_KEY_FILE
    env.user=config.AWS_USER_NAME
    env.connection_attempts=10
    
    print(env.hosts)
    return 


def _get_instance_url(x):
    return x.public_dns_name

def _get_ec2_connection():
    """ Creates an EC2 Connection for the specified region.
    """
    return connect_to_region(config.AWS_REGION, aws_access_key_id=config.AWS_API_KEY, aws_secret_access_key=config.AWS_SECRET_KEY)



