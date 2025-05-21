import dns.resolver

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    BACKGROUND_MAGENTA = '\033[105m'
    BACKGROUND_WHITE = '\033[47m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    ORANGE = '\033[38;5;208m'

def get_dmarc_policy(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_record = ''.join(str(rdata))
            txt_record = txt_record.replace('"',"")
            if 'v=DMARC1' in txt_record:
                for part in txt_record.split(';'):
                    part = part.strip()
                    if "p=" in part and "sp=" not in part:
                        policy = part[2:]
                        if policy == "none" or policy == "p=none":
                            return f"{bcolors.FAIL}"+policy+f"{bcolors.ENDC}" + f" (" + part + f")"
                        elif policy == "quarantine" or policy == "p=quarantine":
                            return f"{bcolors.YELLOW}"+policy+f"{bcolors.ENDC}" + f" (" + part + f")"
                        elif policy == "reject" or policy == "p=reject":
                            return f"{bcolors.OKGREEN}"+policy+f"{bcolors.ENDC}" + f" (" + part + f")"
                        else:
                            return policy + f" (" + part + f")"
        return "--"
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return "--"
    except Exception as e:
        return f"Error: {e}"

# List of domains to check
domains = [
]

counts = {
  "none": 0,
  "quarantine": 0,
  "reject": 0,
  "missing": 0,
}

print(f"*"*50)

for domain in domains:
    policy = get_dmarc_policy(domain)
    print(f" {bcolors.WARNING}" + domain + f": " + policy + f"")
    if "none" in policy: counts["none"] += 1
    elif "quarantine" in policy: counts["quarantine"] += 1
    elif "reject" in policy: counts["reject"] += 1
    else: counts["missing"] += 1
    
total = counts["none"] + counts["quarantine"] + counts["reject"] + counts["missing"]

nonePercent = round((counts["none"]/total*100), 2)
quarantinePercent = round((counts["quarantine"]/total*100), 2)
rejectPercent = round((counts["reject"]/total*100), 2)
missingPercent = round((counts["missing"]/total*100), 2)

print(f"{bcolors.ENDC}",end="")

print(f"*"*50)

print(f"total scanned: "+str(total))
print(f" {bcolors.WARNING}none{bcolors.ENDC}: {bcolors.FAIL}" + str(counts["none"]) + f"{bcolors.ENDC} ({bcolors.WARNING}" + str(nonePercent) + f"{bcolors.ENDC}%)")
print(f" {bcolors.WARNING}quarantine{bcolors.ENDC}: {bcolors.YELLOW}"+ str(counts["quarantine"]) + f"{bcolors.ENDC} ({bcolors.WARNING}" + str(quarantinePercent) + f"{bcolors.ENDC}%)")
print(f" {bcolors.WARNING}reject{bcolors.ENDC}: {bcolors.OKGREEN}"+ str(counts["reject"]) + f"{bcolors.ENDC} ({bcolors.WARNING}" + str(rejectPercent) + f"{bcolors.ENDC}%)")
print(f" {bcolors.WARNING}missing or malformed{bcolors.ENDC}: {bcolors.OKGREEN}"+ str(counts["missing"]) + f"{bcolors.ENDC} ({bcolors.WARNING}" + str(missingPercent) + f"{bcolors.ENDC}%)")

print(f"*"*50)