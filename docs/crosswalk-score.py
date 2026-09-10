# row: (id, label, family, derivable, f_171, f_pci, f_cjis)
rows = [
(1,"Account lifecycle automation","AC",1,2,1,2),
(2,"Privileged account inventory and separation of duties","AC",1,2,2,2),
(3,"Least privilege on roles and policies","AC",1,2,2,2),
(4,"Just-in-time / time-bound elevation","AC",1,1,1,1),
(5,"Session timeout and termination","AC",1,2,2,2),
(6,"Remote access control and encryption","AC",1,2,2,2),
(7,"Disable accounts on suspicious activity","AC",1,1,1,1),
(8,"External system and service connections","AC",1,1,1,1),
(9,"Periodic access review / recertification","AC",1,1,1,1),
(10,"Wireless access restriction and rogue AP detection","AC",0,1,0,1),
(11,"Phishing-resistant MFA for user accounts","IA",1,2,1,2),
(12,"Non-user and service account authentication","IA",1,1,2,1),
(13,"Credential and secret rotation","IA",1,2,2,2),
(14,"Password / authenticator strength policy","IA",1,2,2,2),
(15,"Identity proofing and enrollment","IA",0,1,0,0),
(16,"Log event type definition and coverage","AU",1,2,2,2),
(17,"Centralized tamper-resistant log storage","AU",1,2,2,2),
(18,"Log retention period","AU",1,2,1,2),
(19,"Log review cadence and evidence of review","AU",1,1,1,1),
(20,"Time synchronization for log correlation","AU",1,2,2,2),
(21,"Log access restriction","AU",1,2,2,2),
(22,"Baseline configuration defined","CM",1,2,2,2),
(23,"Configuration drift detection","CM",1,1,1,1),
(24,"Change approval workflow","CM",1,2,1,2),
(25,"Least functionality / disable unnecessary services","CM",1,2,2,2),
(26,"Asset inventory completeness","CM",1,2,2,2),
(27,"Software and resource integrity verification","CM",1,2,1,2),
(28,"Encryption in transit","SC",1,2,2,2),
(29,"Encryption at rest","SC",1,2,1,2),
(30,"Cryptographic key management and rotation","SC",1,2,1,2),
(31,"Key ceremony split knowledge and dual control","SC",0,0,0,0),
(32,"Network segmentation and traffic flow enforcement","SC",1,2,1,2),
(33,"Boundary protection, ingress and egress restriction","SC",1,2,2,2),
(34,"Denial of service protection effectiveness","SC",1,1,0,1),
(35,"Segmentation validated by penetration test","SC",0,0,0,0),
(36,"Vulnerability scanning and remediation","RA",1,2,1,2),
(37,"Malware protection","SI",1,2,2,2),
(38,"File and resource integrity monitoring","SI",1,1,2,1),
(39,"Flaw remediation timelines","SI",1,2,1,2),
(40,"Backup configuration and encryption","CP",1,2,1,2),
(41,"Recovery and disaster recovery exercise","CP",0,0,0,0),
(42,"SBOM and component provenance","SR",1,1,1,1),
(43,"Incident response plan testing","IR",0,0,0,0),
(44,"Security awareness training completion","AT",0,1,1,1),
(45,"Role-based secure development training","AT",0,1,1,0),
(46,"Personnel screening and background checks","PS",0,1,1,0),
]

def pct(n,d): return 100.0*n/d

tot_max = len(rows)*6
tot = sum(r[4]+r[5]+r[6] for r in rows)
print(f"rows: {len(rows)}   families: {len(set(r[2] for r in rows))}")
print(f"OVERALL artifact-level overlap: {tot}/{tot_max} = {pct(tot,tot_max):.1f}%")

der = [r for r in rows if r[3]==1]
nder = [r for r in rows if r[3]==0]
dtot = sum(r[4]+r[5]+r[6] for r in der)
print(f"\ninfrastructure-derivable rows: {len(der)}  ({pct(len(der),len(rows)):.0f}% of set)")
print(f"DERIVABLE-ONLY overlap: {dtot}/{len(der)*6} = {pct(dtot,len(der)*6):.1f}%")
ntot = sum(r[4]+r[5]+r[6] for r in nder)
print(f"NON-derivable rows: {len(nder)}   overlap: {ntot}/{len(nder)*6} = {pct(ntot,len(nder)*6):.1f}%")

print("\nper-pair (all rows):")
for i,name in [(4,"FedRAMP 20x <-> NIST 800-171 r3"),(5,"FedRAMP 20x <-> PCI DSS 4.0.1"),(6,"FedRAMP 20x <-> CJIS 6.1")]:
    s=sum(r[i] for r in rows); print(f"  {name}: {s}/{len(rows)*2} = {pct(s,len(rows)*2):.1f}%")
print("\nper-pair (derivable rows only):")
for i,name in [(4,"FedRAMP 20x <-> NIST 800-171 r3"),(5,"FedRAMP 20x <-> PCI DSS 4.0.1"),(6,"FedRAMP 20x <-> CJIS 6.1")]:
    s=sum(r[i] for r in der); print(f"  {name}: {s}/{len(der)*2} = {pct(s,len(der)*2):.1f}%")

print("\nscore distribution (all pairwise judgments):")
from collections import Counter
c=Counter()
for r in rows:
    for i in (4,5,6): c[r[i]]+=1
for k in sorted(c, reverse=True):
    print(f"  score {k}: {c[k]} ({pct(c[k],sum(c.values())):.1f}%)")

print("\nsensitivity: if every PCI judgment is downgraded one step (floor 0):")
alt = sum(r[4]+max(0,r[5]-1)+r[6] for r in rows)
print(f"  overall -> {pct(alt,tot_max):.1f}%")
altd = sum(r[4]+max(0,r[5]-1)+r[6] for r in der)
print(f"  derivable-only -> {pct(altd,len(der)*6):.1f}%")
print("\nsensitivity: excluding CJIS entirely (harder test):")
hard = sum(r[4]+r[5] for r in rows)
print(f"  overall (171+PCI only) -> {pct(hard,len(rows)*4):.1f}%")
hardd = sum(r[4]+r[5] for r in der)
print(f"  derivable-only (171+PCI only) -> {pct(hardd,len(der)*4):.1f}%")
