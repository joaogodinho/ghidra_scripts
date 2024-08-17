# Opens the default browser and searches MSDN for the currently selected token
#@author jcfg
#@category jcfg
#@keybinding F6
#@menupath jcfg.MSDNSearch
#@toolbar 
import webbrowser

MSDN_SEARCH = 'https://learn.microsoft.com/en-us/search/?scope=Desktop&category=Documentation&terms='

def main():
    token = currentLocation().getTokenName()
    if token:
        webbrowser.open(MSDN_SEARCH + token)
        # Personal addition so I can say "I've saved X hours with this script"
        # total_time = 0
        # with open('/home/<username>/msdn_time_saved.txt', 'r') as f:
        #     total_time = int(f.read())
        # with open('/home/<username>/msdn_time_saved.txt', 'w') as f:
        #     f.write(str(total_time + 10))

if __name__ == '__main__':
    main()
