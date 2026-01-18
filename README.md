Setup procedure:

```
mkdir project
cd project/
sudo apt update
sudo apt install -y git
git --version
sudo apt install -y python3 python3-pip
python3 --version
pip3 --version
```
```
git init
git remote add origin git@github.com:Tevfik-Can/Net4000-Project.git
git branch -M main
touch test.txt
git add .
git commit -m "test" (Told me to add my email and username)
git config --global user.email "EMAIL@gmail.com"
git config --global user.name "GITHUB-USERNAME"
git commit -m "test" (Told me no SSH key found)
git push -u origin main
```
```
ls ~/.ssh/id_*.pub
sudo ls ~/.ssh/id_*.pub (If nothing is found, proceed with next 3)
ssh-keygen -t ed25519 -C "EMAIL@gmail.com"
cat ~/.ssh/id_ed25519.pub
```
Go to https://github.com/settings/keys
Click New SSH key
Give it a title (e.g., “Ubuntu VM key”)
Paste the copied key into the key field
Click Add SSH key
Then:
```
ssh -T git@github.com
git push -u origin main
git status
```
