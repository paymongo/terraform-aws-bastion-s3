#!/bin/bash -x
yum -y update --security
amazon-linux-extras install epel -y
yum -y install autoconf wget automake pam-devel libtool

# Build google-authentiactor
AUTHENTICATOR_LIBPAM_VERSION=1.09
AUTHENTICATOR_LIBPAM_PREFIX=google-authenticator-libpam-$AUTHENTICATOR_LIBPAM_VERSION
wget https://github.com/google/google-authenticator-libpam/archive/refs/tags/$AUTHENTICATOR_LIBPAM_VERSION.tar.gz \
  -O $AUTHENTICATOR_LIBPAM_PREFIX.tar.gz
tar -xf $AUTHENTICATOR_LIBPAM_PREFIX.tar.gz
cd $AUTHENTICATOR_LIBPAM_PREFIX && \
  ./bootstrap.sh && \
  ./configure --exec-prefix=/usr && \
  make && \
  make install && \
  cd ../

cat > /etc/pam.d/sshd << 'EOF'
#%PAM-1.0
auth       required     /usr/lib/security/pam_google_authenticator.so nullok
auth       required     pam_permit.so

auth       required     pam_sepermit.so
#auth       substack     password-auth
auth       include      postlogin
# Used with polkit to reauthorize users in remote sessions
-auth      optional     pam_reauthorize.so prepare
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
# pam_selinux.so close should be the first session rule
session    required     pam_selinux.so close
session    required     pam_loginuid.so
# pam_selinux.so open should only be followed by sessions to be executed in the user context
session    required     pam_selinux.so open env_params
session    required     pam_namespace.so
session    optional     pam_keyinit.so force revoke
#session    include      password-auth
session    include      postlogin
# Used with polkit to reauthorize users in remote sessions
-session   optional     pam_reauthorize.so prepare
EOF

# Enable mfa
sed -i "s/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g" /etc/ssh/sshd_config
echo -e "\\nAuthenticationMethods publickey,keyboard-interactive" >> /etc/ssh/sshd_config


##########################
## ENABLE SSH RECORDING ##
##########################

# Create a new folder for the log files
mkdir /var/log/bastion

# Allow ec2-user only to access this folder and its content
chown ec2-user:ec2-user /var/log/bastion
chmod -R 770 /var/log/bastion
setfacl -Rdm other:0 /var/log/bastion

# Update sshd default port to public_ssh_port
sed -i "s/#Port 22/Port ${public_ssh_port}/g" /etc/ssh/sshd_config

# Make OpenSSH execute a custom script on logins
echo -e "\\nForceCommand /usr/bin/fc" >> /etc/ssh/sshd_config

# Block some SSH features that bastion host users could use to circumvent the solution
awk '!/X11Forwarding/' /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config

cat > /usr/bin/fc << 'EOF'
#!/bin/bash
function _sigint() {
  echo -e '\nAborted'
  exit 1
}

trap _sigint SIGINT

for script in /etc/fc.d/* ; do
  if [ -r $script ] && [ -x $script ]; then
    . $script
    if [ $? -ne 0 ]; then
      echo "Access denied"
      exit 1
    fi
  fi
done
EOF
chmod a+x /usr/bin/fc

mkdir /etc/fc.d

cat > /etc/fc.d/0.setup-google-authenticator.sh << 'EOF'
#!/bin/bash

# Don't force google-authenticator if the user is in no2fa group
if groups "$USER" | grep -q 'no2fa'; then
    echo "no2fa user detected: skipping google-authenticator..."
else
    until [ -f "$HOME/.google_authenticator" ]; do
      if ! [[ -t 1 ]] || [[ "$SSH_ORIGINAL_COMMAND" =~ ^(rsync|nc|scp) ]]; then
        echo "MFA setup required"
        exit 1
      else
        echo -e "\nWelcome $USER. Please follow the prompts to setup your MFA device..."
        umask 0066
        google-authenticator -td -r 10 -R 30 -w 10 -f
        if [ $? -ne 0 ]; then
          echo "MFA setup failed"
          exit 1;
        fi

        if [ -f .google_authenticator ]; then
          chmod 600 .google_authenticator
          echo "MFA enabled for $USER"
        else
          echo "MFA setup is mandatory"
        fi
      fi
    done

    trap - SIGINT
fi
EOF
chmod a+x /etc/fc.d/0.setup-google-authenticator.sh

cat > /etc/fc.d/9.shell << 'EOF'
# Check that the SSH client did not supply a command
if [[ -z $SSH_ORIGINAL_COMMAND ]]; then

  # The format of log files is /var/log/bastion/YYYY-MM-DD_HH-MM-SS_user
  LOG_FILE="`date --date="today" "+%Y-%m-%d_%H-%M-%S"`_`whoami`"
  LOG_DIR="/var/log/bastion/"

  # Print a welcome message
  echo ""
  echo "NOTE: This SSH session will be recorded"
  echo "AUDIT KEY: $LOG_FILE"
  echo ""

  # I suffix the log file name with a random string. I explain why later on.
  SUFFIX=`mktemp -u _XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`

  # Wrap an interactive shell into "script" to record the SSH session
  script -qf --timing=$LOG_DIR$LOG_FILE$SUFFIX.time $LOG_DIR$LOG_FILE$SUFFIX.data --command=/bin/bash

else

  # If the module consumer wants to allow remote commands (for ansible or other) then allow that command through.
  if [ "${allow_ssh_commands}" == "true" ]; then
    exec /bin/bash -c "$SSH_ORIGINAL_COMMAND"
  else
    # The "script" program could be circumvented with some commands (e.g. bash, nc).
    # Therefore, I intentionally prevent users from supplying commands.

    echo "This bastion supports interactive sessions only. Do not supply a command"
    exit 1
  fi
fi
EOF
chmod a+x /etc/fc.d/9.shell

# Bastion host users could overwrite and tamper with an existing log file using "script" if
# they knew the exact file name. I take several measures to obfuscate the file name:
# 1. Add a random suffix to the log file name.
# 2. Prevent bastion host users from listing the folder containing log files. This is done
#    by changing the group owner of "script" and setting GID.
chown root:ec2-user /usr/bin/script
chmod g+s /usr/bin/script

# 3. Prevent bastion host users from viewing processes owned by other users, because the log
#    file name is one of the "script" execution parameters.
mount -o remount,rw,hidepid=2 /proc
awk '!/proc/' /etc/fstab > temp && mv temp /etc/fstab
echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab

# Restart the SSH service to apply /etc/ssh/sshd_config modifications.
service sshd restart

############################
## EXPORT LOG FILES TO S3 ##
############################

cat > /usr/bin/bastion/sync_s3 << 'EOF'
#!/usr/bin/env bash

# Copy log files to S3 with server-side encryption enabled.
# Then, if successful, delete log files that are older than a day.
LOG_DIR="/var/log/bastion/"
aws s3 cp $LOG_DIR s3://${bucket_name}/logs/ --sse --region ${aws_region} --recursive && find $LOG_DIR* -mtime +1 -exec rm {} \;

EOF

chmod 700 /usr/bin/bastion/sync_s3

#######################################
## CREATE no2fa GROUP
#######################################
groupadd no2fa
# You can add 2fa for ec2-user by executing google-authenticator command
usermod -aG no2fa ec2-user

#######################################
## SYNCHRONIZE USERS AND PUBLIC KEYS ##
#######################################

# Bastion host users should log in to the bastion host with their personal SSH key pair.
# The public keys are stored on S3 with the following naming convention: "username.pub".
# This script retrieves the public keys, creates or deletes local user accounts as needed,
# and copies the public key to /home/username/.ssh/authorized_keys

cat > /usr/bin/bastion/sync_users << 'EOF'
#!/usr/bin/env bash

# The file will log user changes
LOG_FILE="/var/log/bastion/users_changelog.txt"

# The function returns the user name from the public key file name.
# Example: public-keys/sshuser.pub => sshuser
get_user_name () {
	echo "$1" | sed -e "s/.*\///g" | sed -e 's/^no2fa-//' | sed -e "s/\.pub//g"
}

# For each public key available in the S3 bucket
aws s3api list-objects --bucket ${bucket_name} --prefix public-keys/ --region ${aws_region} --output text --query 'Contents[?Size>`0`].Key' | tr '\t' '\n' > ~/keys_retrieved_from_s3
while read line; do
  USER_NAME="`get_user_name "$line"`"

  # Make sure the user name is alphanumeric
  if [[ "$USER_NAME" =~ ^[a-z][-a-z0-9]*$ ]]; then

    # Create a user account if it does not already exist
    cut -d: -f1 /etc/passwd | grep -qx $USER_NAME
    if [ $? -eq 1 ]; then
      /usr/sbin/adduser $USER_NAME && \
      mkdir -m 700 /home/$USER_NAME/.ssh && \
      chown $USER_NAME:$USER_NAME /home/$USER_NAME/.ssh && \
      echo "$line" >> ~/keys_installed && \
      echo "`date --date="today" "+%Y-%m-%d %H-%M-%S"`: Creating user account for $USER_NAME ($line)" >> $LOG_FILE

      if [[ "$line" == "public-keys/no2fa-"* ]]; then
        echo "no2fa user. Adding $USER_NAME to group no2fa"
        usermod -aG no2fa $USER_NAME
      fi
    fi

    # Copy the public key from S3, if an user account was created from this key
    if [ -f ~/keys_installed ]; then
      grep -qx "$line" ~/keys_installed
      if [ $? -eq 0 ]; then
        aws s3 cp s3://${bucket_name}/$line /home/$USER_NAME/.ssh/authorized_keys --region ${aws_region}
        chmod 600 /home/$USER_NAME/.ssh/authorized_keys
        chown $USER_NAME:$USER_NAME /home/$USER_NAME/.ssh/authorized_keys
      fi
    fi

  fi
done < ~/keys_retrieved_from_s3

# Remove user accounts whose public key was deleted from S3
if [ -f ~/keys_installed ]; then
  sort -uo ~/keys_installed ~/keys_installed
  sort -uo ~/keys_retrieved_from_s3 ~/keys_retrieved_from_s3
  comm -13 ~/keys_retrieved_from_s3 ~/keys_installed | sed "s/\t//g" > ~/keys_to_remove
  while read line; do
    USER_NAME="`get_user_name "$line"`"
    echo "`date --date="today" "+%Y-%m-%d %H-%M-%S"`: Removing user account for $USER_NAME ($line)" >> $LOG_FILE
    /usr/sbin/userdel -r -f $USER_NAME
  done < ~/keys_to_remove
  comm -3 ~/keys_installed ~/keys_to_remove | sed "s/\t//g" > ~/tmp && mv ~/tmp ~/keys_installed
fi

EOF

chmod 700 /usr/bin/bastion/sync_users

##############################
## INSTALL SECURITY UPDATES ##
##############################

# Security updates are installed by yum. If script is updated (package util-linux)
# then the setuid bit needs to be recovered. Otherwise clients can not loging.

cat > /usr/bin/bastion/yum_update << 'EOF'
#!/usr/bin/env bash

yum -y update --security

chown root:ec2-user /usr/bin/script
chmod g+s /usr/bin/script

EOF

chmod 700 /usr/bin/bastion/yum_update


###########################################
## SCHEDULE SCRIPTS AND SECURITY UPDATES ##
###########################################

cat > ~/mycron << EOF
*/5 * * * * /usr/bin/bastion/sync_users
0 0 * * * /usr/bin/bastion/yum_update
${sync_logs_cron_job}
EOF
crontab ~/mycron
rm ~/mycron


#########################################
## Add Custom extra_user_data_content ##
#######################################

${extra_user_data_content}
