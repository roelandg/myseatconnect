
# Installation

### Clone this project
```shell
git clone git@github.com:roelandg/myseatconnect.git
```
### Update the *config.json* as below

```json
{
  "USERNAME": "<email addres>",
  "PASSWORD": ""
}
```

# USAGE

### Run any of the following commands

```shell
# Get all info available (which is know so-far)
python myseatconnect.py get 

# Set the  minimum charge level to 30%
python myseatconnect.py set minSocPercentage 30

# Make a wake-up request
python myseatconnect.py call wakeup-request
```