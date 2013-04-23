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
communication_rule = "locust-{0}".format(config.PROJECT)

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
  aws_connection = _get_aws_connection()
  search = aws_connection.get_all_instances(filters=master_filter) 
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
  """ stop locust with extreme prejiduce 
  """
  sudo('killall -9 screen')

@parallel
def configure():
    """ Configures packages on the virtual OS.

    """
    sudo('apt-get update -q')
    sudo('apt-get install -q htop build-essential python-pip python-dev libevent-dev libzmq-dev --assume-yes')
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
      _create_security_group()
      _create_instances()

def terminate():
    """ Terminates all instances with the current
    """
    _terminate_instances()

@parallel
def upload_directory():
    """ puts files on all servers
    """
    global remote_folder
    sudo('mkdir -p {0}'.format(remote_folder))
    with lcd(config.LOCAL_DIRECTORY):
      put("*", remote_folder,True)

def _set_env():
    aws_connection = _get_aws_connection()

    search = aws_connection.get_all_instances(filters=filter) 
    
    for result in search:
      env.hosts = env.hosts + map(_get_instance_url, result.instances)
      
    env.key_filename = config.LOCAL_AWS_KEY_FILE
    env.user=config.AWS_USER_NAME
    env.connection_attempts=10
    
    print(env.hosts)
    return 

def _terminate_security_group():
    aws_connection = _get_aws_connection()
    security_groups = aws_connection.get_all_security_groups()
    specific_security_group = [x for x in security_groups if x.name == communication_rule]
    if len(specific_security_group) == 1:
      has_instances = len([x for x in specific_security_group[0].instances()]) > 0
      if not has_instances:
        aws_connection.delete_security_group(communication_rule)
      else:
        print(red("Security group {0} has instances".format(communication_rule)))
    else:
      print(red("Security group {0} does not exist".format(communication_rule)))

def _create_security_group():
    aws_connection = _get_aws_connection()
    security_group_names = [x.name for x in aws_connection.get_all_security_groups()]
    if communication_rule not in security_group_names:
      print(red("Security group {0} does not exist".format(communication_rule)))
      print('Creating.....')
      security_group = aws_connection.create_security_group(communication_rule, 'locust communications')
      security_group.authorize('tcp', 5557, 5558, src_group=security_group)
      security_group.authorize('tcp', 8089, 8089, '0.0.0.0/0')
      security_group.authorize('tcp', 22, 22, '0.0.0.0/0')

def _create_instances():
    aws_connection = _get_aws_connection()

    reservation = aws_connection.run_instances(config.AMI_ID, key_name=config.AWS_KEY_FILE,instance_type=config.AWS_INSTANCE_SIZE,
    security_group_ids=[communication_rule], min_count=count, max_count=count)
    
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

def _terminate_instances():
    aws_connection = _get_aws_connection()
    search = aws_connection.get_all_instances(filters=filter) 
    
    for reservation in search:
      print('found {0} {1}'.format(len(reservation.instances),type))
      for instance in reservation.instances:
        print(red('Terminating instance {0}'.format(instance.id)))
        aws_connection.terminate_instances([instance.id])
    _terminate_security_group()

def _get_instance_url(x):
    return x.public_dns_name

def _get_aws_connection():
    """ Creates an EC2 Connection for the specified region.
    """
    aws_connection = connect_to_region(config.AWS_REGION, aws_access_key_id=config.AWS_API_KEY, aws_secret_access_key=config.AWS_SECRET_KEY)
    print('Connected to {0}'.format(aws_connection))
    return aws_connection



