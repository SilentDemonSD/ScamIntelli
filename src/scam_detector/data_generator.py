import json
import random
from pathlib import Path
from typing import List

from src.utils.logging import get_logger

logger = get_logger(__name__)

OUTPUT_PATH = Path("models/training_data.jsonl")

SCAM_TEMPLATES = {
    "digital_arrest": [
        "This is Cyber Crime Department. Your Aadhaar has been used for illegal activities. You are under digital arrest. Do not disconnect.",
        "I am Inspector {name} from CBI. A case has been registered against you. Transfer 50000 to settle.",
        "Your phone number is linked to money laundering case. You must verify now or face arrest.",
        "Cyber crime branch here. Your bank account is being used for fraud. Stay on call.",
        "This is Delhi Police Cyber Cell. FIR filed against your Aadhaar number. Pay fine immediately.",
        "Supreme Court order against you. Digital arrest warrant issued. Do not cut the call.",
        "I am calling from Enforcement Directorate. Your PAN is linked to hawala transactions.",
        "NCB calling. Drugs found in parcel booked under your name. Stay on video call.",
        "Sir aapke khilaf arrest warrant jari ho gaya hai. Abhi settlement karo warna jail.",
        "Yeh CBI ka official call hai. Aapka Aadhaar se 50 fake account khule hain.",
        "Aapke phone number se fraud hua hai. 2 ghante mein police aayegi ghar pe.",
        "Digital arrest under section 420. Bail ke liye 1 lakh transfer karo turant.",
    ],
    "kyc_phishing": [
        "Dear customer, your KYC is pending. Update now or account will be blocked: {link}",
        "Your SBI account will be suspended. Click link to verify KYC immediately.",
        "URGENT: Complete KYC verification for your Paytm wallet. Visit {link}",
        "RBI notification: KYC update mandatory. Failure will result in account freeze.",
        "Aapka bank account block ho jayega agar KYC update nahi kiya 24 hours mein.",
        "Dear user your PAN card not linked to bank. Complete verification: {link}",
        "ICICI Bank: Your account KYC expired. Update at {link} to avoid deactivation.",
        "Aapka Aadhaar link nahi hai bank se. Abhi karo nahi toh account band.",
    ],
    "investment_fraud": [
        "Invest 10000 today and earn 1 lakh in 30 days. Guaranteed returns!",
        "Join our WhatsApp group for stock tips. 500% returns guaranteed.",
        "SEBI registered investment advisor. Minimum 50% monthly returns.",
        "Trading signals group join karo. Daily 10000 profit pakka.",
        "Crypto mining opportunity. Invest 5000, earn 50000 per month.",
        "IPO allotment guaranteed. Transfer registration fee of 2000.",
        "Share market mein paisa double karo. 100% safe investment.",
        "Binary options trading. Risk free returns. Join now limited seats.",
    ],
    "job_scam": [
        "Work from home job. Earn 50000 monthly. Just pay 500 registration fee.",
        "Amazon hiring data entry operators. No experience needed. Apply with fee.",
        "Part time typing job. 2000 per day. Registration charges 1000.",
        "Flipkart product review job. Earn per review. Pay training fee first.",
        "Online task completion job. Daily 5000. Deposit 2000 to start.",
        "Telegram group mein join karo. Like and subscribe karke 500 daily kamao.",
        "Government job vacancy. Pay 3000 for form processing fee.",
        "International company hiring Indians. Work from mobile. Fee 1500.",
    ],
    "lottery_prize": [
        "Congratulations! You have won 25 lakh in WhatsApp Lucky Draw!",
        "You are selected for Google Lottery 2024. Claim 50 lakh prize money.",
        "KBC lottery winner! Pay processing fee of 5000 to claim 1 crore.",
        "International lottery winner. Transfer tax payment to receive prize.",
        "Aapko lucky draw mein 10 lakh mile hain. Claim karne ke liye 2000 bhejo.",
        "Jio recharge lucky winner. You won iPhone 15. Pay shipping charges.",
        "Dear customer your number selected for 5 lakh cashback. Pay GST to claim.",
        "Facebook lottery 2024. You won $100000. Send processing fee.",
    ],
    "romance_scam": [
        "I am a US military officer. I have gold stuck in customs. Need money to release.",
        "My gift for you is stuck at Indian customs. Pay 5000 duty charges.",
        "I love you darling. Send me money for flight ticket to meet you.",
        "I am stuck abroad with medical emergency. Please send 20000 urgent.",
        "My inheritance is locked. Help me with 10000 and I'll share 50% with you.",
        "Baby I want to send you gift from London. Pay customs clearance fee.",
        "I am oil rig engineer. My salary stuck. Please help with 15000.",
        "Jaan mujhe visa ke liye paise chahiye. 30000 bhejo please.",
    ],
    "tech_support": [
        "Your computer has been infected with virus. Call Microsoft support at {phone}.",
        "Windows security alert! Your system is compromised. Install AnyDesk now.",
        "Apple ID locked due to suspicious activity. Call support immediately.",
        "Your antivirus subscription expired. Renew now or lose all data.",
        "Firewall breach detected on your network. Download TeamViewer for remote fix.",
        "Aapke computer mein malware hai. Abhi call karo support number pe.",
        "Microsoft calling. Your license expired. Pay 5000 for renewal.",
        "System compromised. Hackers accessing your bank. Install remote access immediately.",
    ],
    "customs_parcel": [
        "Your parcel seized at customs. Drugs found. Pay 10000 clearance fee.",
        "DHL courier detained at Mumbai airport. Pay duty charges to release.",
        "FedEx package with illegal contents under your name. Call customs officer.",
        "International parcel with contraband detected. Legal action if not cleared.",
        "Aapka parcel customs mein ruka hai. 15000 duty charges bhejo.",
        "Courier seized by narcotics. Pay fine or face criminal charges.",
        "Your Amazon international order held at customs. Pay import duty {link}.",
        "Parcel from London detained. Contact officer to avoid legal action.",
    ],
    "loan_fraud": [
        "Pre-approved personal loan of 5 lakh. Just pay 2000 processing fee.",
        "Instant loan approved. Low CIBIL no problem. Pay documentation charges.",
        "Loan disbursement ready. Transfer GST charges of 3000 to release amount.",
        "5 minute loan approval. No documents needed. Registration fee 1500.",
        "Aapka loan approve ho gaya hai. Processing fee of 5000 transfer karo.",
        "Bank pre-approved loan offer. Pay advance EMI to activate.",
        "Zero interest loan for government employees. Just pay 1000 stamp duty.",
        "Loan of 10 lakh sanctioned. Pay insurance charges to proceed.",
    ],
    "crypto_scam": [
        "Bitcoin investment opportunity. 10x returns in 30 days guaranteed.",
        "Join our crypto trading group. Daily signals. Initial deposit 5000.",
        "Free crypto airdrop! Connect your wallet at {link} to claim tokens.",
        "NFT presale exclusive access. Mint now before price goes up 100x.",
        "Staking rewards of 500% APY. Deposit crypto to start earning.",
        "Mining pool membership. Passive income from Bitcoin mining.",
        "DeFi yield farming. Put 10000 get 100000 in one month.",
        "New token launching. Early investors get 1000% returns.",
    ],
    "refund_scam": [
        "Your refund of 15000 is pending. Click {link} to process.",
        "Excess amount of 5000 credited to your account. Return via UPI.",
        "Tax refund of 8000 available. Enter bank details to receive.",
        "Insurance claim refund ready. Pay processing fee of 500.",
        "Aapka refund bank mein aa gaya hai. Verify karne ke liye OTP bhejo.",
        "Wrong transfer of 25000 to your account. Please return immediately.",
        "Order cancelled. Refund initiated. Click link to verify bank account.",
        "Government subsidy refund. Enter Aadhaar and bank details.",
    ],
    "qr_code_scam": [
        "I am buyer. Scan this QR code to receive payment of 5000.",
        "Scan QR to get your OLX payment. Amount 8000.",
        "Payment QR code for your product. Scan to receive money.",
        "Refund via QR code. Scan to get 3000 back.",
        "Main buyer hun. QR scan karo payment aa jayega 10000.",
        "OLX payment: Scan this QR. Money will be credited instantly.",
    ],
    "sextortion": [
        "I have your private video from webcam. Pay 50000 or I share with contacts.",
        "Your private photos recorded. Send money or I post online.",
        "Video call recorded. Pay 20000 or I send to your family.",
        "Adult website visit recorded. Your contacts list obtained. Pay now.",
        "Tumhara video mere paas hai. 30000 do nahi toh viral karunga.",
        "Pay to delete your private content. 10000 last chance.",
    ],
    "sim_swap": [
        "Your SIM needs upgrade from 4G to 5G. Share OTP for activation.",
        "Telecom verification required. Your SIM will be deactivated in 2 hours.",
        "Jio 5G upgrade offer. Share verification code to activate.",
        "Your mobile number being ported. Share OTP to stop.",
        "SIM blocked due to KYC issue. Share Aadhaar OTP to reactivate.",
        "Free 5G SIM upgrade. Just verify with OTP sent to your number.",
    ],
}

BENIGN_MESSAGES = [
    "Hey, are you free for lunch today?",
    "Can you send me the project report by evening?",
    "Happy birthday! Wishing you a great year ahead.",
    "Meeting rescheduled to 3 PM tomorrow. Please confirm.",
    "Thanks for your help with the presentation yesterday.",
    "Kal ka plan cancel ho gaya hai. Kuch aur sochte hain.",
    "Bhai dinner pe chalein aaj? Naye restaurant mein.",
    "Mom ka call aaya tha. Ghar pe aana hai weekend pe.",
    "Movie dekhne chalein Saturday ko? New release hai.",
    "Assignment submit kar diya maine. Tumne kiya?",
    "Good morning! How's your day going?",
    "Please review the document I shared on Google Drive.",
    "Gym jaana hai aaj shaam ko? 6 baje chalte hain.",
    "Bill split kar lete hain. 500 each aata hai.",
    "Traffic bahut hai aaj. Late ho jaunga thoda.",
    "Kya haal hai? Kaafi din ho gaye baat nahi hui.",
    "Can we reschedule our call to next week?",
    "I finished reading the book. It was really good!",
    "Aaj mausam kaisa hai wahan? Yahan toh garmi hai.",
    "Let me know when you reach office, I'll come down.",
    "Papa ka birthday hai next month. Gift ideas batao.",
    "I'll be working from home tomorrow.",
    "Grocery list bhej do, main market ja raha hun.",
    "Netflix pe naya show dekha? Kaafi accha hai.",
    "Flight confirmed for next Friday. Terminal 3.",
    "Doctor appointment hai 11 baje. Thoda late aaunga.",
    "Rent transfer kar diya hai. Check karo.",
    "Parking mein gaadi laga di. 5th floor pe aa jao.",
    "Wifi password kya hai? Connect nahi ho raha.",
    "Tea ya coffee? Main canteen ja raha hun.",
    "Resume update kar liya. Review kar doge please?",
    "Sharma ji ne invite kiya hai dinner pe. Chalein?",
    "AC ki service karwani hai. Technician ka number hai?",
    "Mummy ne poha banaya hai. Aake kha lo.",
    "Class cancel hai aaj. Professor sick leave pe hain.",
    "Cab book kar lo. 8 baje nikalna hai.",
    "Cousins aa rahe hain Diwali pe. Room ready karna padega.",
    "Match dekh rahe ho? India bowling kar raha hai.",
    "Presentation acchi gayi aaj. Boss ne appreciate kiya.",
    "Headache ho raha hai. Koi medicine hai tumhare paas?",
    "Library mein hun. 2 baje tak free ho jaunga.",
    "Swiggy se order karna hai? Kya khayenge?",
    "New phone lena hai. Budget 20000 hai.",
    "Parking full hai mall mein. Kisi aur jagah chalte hain.",
    "Exam next week hai. Notes share karo please.",
    "Ruko 5 minute, abhi aa raha hun.",
    "Aaj kaafi thak gaya. Early sleep karunga.",
    "Weekend pe goa plan karein? Tickets saste hain.",
    "Kal interview hai. Wish me luck!",
    "Electricity bill pay kar do online. Due date kal hai.",
    "I shared the meeting notes in Slack. Please check.",
    "The weather is really nice today for a walk.",
    "Can you pick up milk on your way home?",
    "I just submitted my tax returns for this year.",
    "The kids have a school event next Wednesday.",
    "Thanks for the birthday wishes everyone!",
    "Just got back from vacation. So much work pending.",
    "Team outing plan karte hain is month end.",
    "Ek aur chai pi lete hain bhai. Thandi ho rahi hai.",
    "Temple jaana hai Sunday. Subah 7 baje niklenge.",
    "IPL ka match dekho aaj. Bahut exciting hai.",
    "Bhai kal lunch pe chalein? Naye restaurant khula hai corner pe.",
    "Kab aa rahe ho tum? Main wait kar raha hun.",
    "Arey yaar, kal ka homework kar liya tune?",
    "Office mein aaj bahut kaam hai, late ho jaunga.",
    "Mummy ne chai banayi hai, aa jao.",
    "Bhai tera charger dede, mera kharab ho gaya.",
    "Subah jaldi uthna hai kal. Alarm laga lena.",
    "Kya plan hai weekend ka? Kuch sochte hain.",
    "Main abhi market mein hun. Kuch chahiye toh batao.",
    "Aaj bahut thak gaya yaar. Sone ja raha hun.",
    "Tune woh video dekhi WhatsApp pe? Bahut funny thi.",
    "Bhai pizza order karte hain aaj.",
    "Kal exam hai, padhai kar raha hun.",
    "Mumma ka phone aaya, unki tabiyat theek nahi hai.",
    "Ghar pe paani nahi aa raha, plumber ko call kar.",
    "Bhai paise wapas karde, 200 the mere.",
    "Shopping karne jaana hai, saath chalogi kya?",
    "Train late hai, 30 minute wait karna padega.",
    "Kal salary aa gayi, party dene ka time aa gaya!",
    "Naya phone liya hai, photo bhej raha hun dekho.",
    "Chai peene chalo canteen mein? 4 baj gaye.",
    "Bhai mere notes photo karke bhej de please.",
    "Doctor ke paas jaana hai, appointment le li hai.",
    "Ye movie bahut boring hai, chalo bahar chalte hain.",
    "Main ghar pahunch gaya, don't worry.",
    "Dinner ready hai, table pe aa jao.",
    "Kal cricket khelne chalein? Ground book kar leta hun.",
    "Meri bike ki servicing karwani hai, kahin acchi jagah batao.",
    "Papa se permission le li, trip pe ja sakte hain.",
    "Bhai tune mera pen dekha kya? Kahi rakh diya tha.",
    "Aaj bahut garmi hai, ice cream khaate hain.",
    "How are you doing? Long time no see!",
    "Please send the invoice for last month's order.",
    "The client meeting went well. They liked our proposal.",
    "Let's catch up over coffee this weekend.",
    "Have you seen the new update? The interface looks great.",
    "I'm running late, start without me.",
    "Just finished a great workout at the gym.",
    "Do you want to carpool tomorrow morning?",
    "The deadline has been extended by a week.",
    "Happy anniversary to you both! Many more years together.",
    "What time does the store close today?",
    "I'll handle the backend, you take care of the frontend.",
    "My laptop needs repair, any suggestions for a service center?",
    "Let me know once you've reviewed the pull request.",
    "The food at that place was amazing! Must visit again.",
    "Can you water my plants while I'm away?",
    "I need to renew my passport before the trip.",
    "Thanks for picking me up from the airport!",
    "The internet is so slow today, can barely stream anything.",
    "Aaj meri anniversary hai. Dinner plan kiya hai bahar.",
    "Yaar ye math problem samajh nahi aa rahi.",
    "Kab miloge? Bahut din ho gaye baat nahi hui properly.",
    "Main ek naya course start karne wala hun online.",
    "Birthday party mein kya gift le jaayein?",
    "Aaj office mein team lunch hai, aa jao.",
    "Newspaper mein aaj interesting article padha.",
    "Garden mein naye phool laga diye hain. Bahut sundar lag rahe hain.",
    "Kal Sunday hai. Poori family ke saath picnic chalte hain.",
    "Bhai parking charges de do, 100 rupees hai.",
    "Yaar meri battery 5% hai, baad mein call karta hun.",
]

ADVERSARIAL_BENIGN = [
    "I need to update my KYC at the bank branch tomorrow morning.",
    "Just transferred 5000 to mom's account. She needed money for groceries.",
    "My PAN card arrived today. Finally linked it with my bank account.",
    "Police uncle came for routine address verification at our house.",
    "Got my income tax refund today! 8000 rupees credited to my account.",
    "I won the college sports competition! Got 10000 cash prize.",
    "Doctor said the surgery will cost 50000. Need to arrange funds urgently.",
    "Bank app is down, can't even check my OTP. So frustrating.",
    "Aadhaar card update ho gaya. Biometrics bhi de diye.",
    "SBI branch mein 2 ghante laga KYC karane mein. Line bahut lambi thi.",
    "Papa ne 1 lakh fixed deposit karwaya hai. Good interest rate mil raha.",
    "CBI raid ki news dekhi? Office ke paas hua kuch.",
    "New SIM card activate karna hai. Store pe jaana padega.",
    "Paytm se wallet top up kar liya. 2000 daale hain.",
    "Cyber crime awareness seminar hai college mein next week.",
    "UPI se payment kiya dukaan pe. 500 rupees kata.",
    "Mera refund aa gaya Amazon se. 1500 back in account.",
    "Investment advisor se mila aaj. SIP start karne ka soch raha hun.",
    "Mutual fund mein 10000 per month invest kar raha hun ab se.",
    "Bank se loan approve ho gaya. 5 lakh personal loan at 10.5%.",
    "Job interview clear ho gaya! Offer letter aayega next week.",
    "Salary credited! Finally 50000 in account after taxes.",
    "SEBI guidelines change hui hain. New rules for mutual funds.",
    "Stock market mein aaj bahut crash hua. Portfolio down 15%.",
    "Google pay se bill pay kiya. Electricity ka 3000 tha.",
    "Customs duty pay karna pada international order pe. 2000 extra laga.",
    "My old laptop sold on OLX. Got 15000. Buyer was nice.",
    "Bank manager se meeting thi. Home loan discuss kiya.",
    "Aadhaar OTP aaya mobile pe. Branch walon ne maanga tha verification ke liye.",
    "FIR file kiya hai chain snatching ka. Police station gaye the.",
    "Income tax return file kiya online. Refund aayega 3 weeks mein.",
    "SIM upgrade kiya 5G. Store pe jakke free mein ho gaya.",
    "Court mein case chal raha hai property ka. Lawyer fees bahut hai.",
    "Credit card bill 25000 aaya. Pay karna padega due date se pehle.",
    "WhatsApp pe group admin ban gaya hun. Organization updates share karunga.",
    "Insurance premium due hai. 12000 pay karna hai is month.",
    "Bhai ne crypto mein invest kiya hai. Thoda risky lagta hai.",
    "Passport renewal ke liye appointment liya hai. Documents ready hain.",
    "Online course ka certificate aaya. 5000 ki fee thi but worth it.",
    "School fees 30000 pay ki. Next installment March mein hai.",
    "ATM se 10000 nikale. Cash chahiye tha electrician ko dene ke liye.",
    "CIBIL score check kiya. 750 aa raha hai, kaafi accha.",
    "GST registration ho gayi business ki. CA ne help kiya.",
    "Mummy ka medical bill 40000 aaya. Insurance se claim karunga.",
    "Train ticket book kiya IRCTC se. UPI se pay kiya 1200.",
    "Car insurance renew karaya. Premium 15000 pada is baar.",
    "Society maintenance ka 5000 dena hai. Deadline kal hai.",
    "EMI deduct ho gayi auto. Home loan ki 22000 har mahine.",
    "Bank ne new debit card bheja. PIN set karna hai ATM pe.",
    "Papa ko pension mili. 30000 har mahine aata hai account mein.",
    "Toll tax de diya UPI se. 250 each way highway pe.",
    "Aaj stock market mein 5000 ka profit hua. Mutual fund bhi upar.",
    "I went to the bank to report a suspicious transaction on my account.",
    "Our company is hiring data entry operators. Send your resume to HR.",
    "I got an alert from my bank about a login from new device. Changed password.",
    "My friend asked for 5000 urgently. I sent via Google Pay.",
    "Just completed the Aadhaar verification at the telecom store.",
    "The police called about a minor traffic violation. Need to pay fine online.",
    "I invested in an IPO last month. Got allotment today!",
    "My wallet was stolen yesterday. Blocked all my cards immediately.",
    "Account verification done at the branch. They needed my latest address proof.",
]

SUBTLE_SCAM_TEMPLATES = {
    "social_engineering": [
        "Hey, I found this great side income opportunity. Want me to share details?",
        "Bhai wohi investment scheme hai jismein Sharma ji ne double kiya paisa. Try karo.",
        "Are you looking for extra income? My team is expanding. Minimum effort, great results.",
        "My friend put only 5000 and is now making 2000 daily. I can connect you.",
        "Ek dost hai jo trading tips deta hai. Small fee leti hai but returns amazing hain.",
        "I have insider info on a stock. Guaranteed to go up 200% next week. Interested?",
        "Bhai ek scheme hai govt backed. 100% returns 6 months mein. Documents bhej de.",
        "There is a verified platform where you can earn passive income. Want the link?",
    ],
    "impersonation": [
        "Hi, this is from your bank's fraud department. We noticed unusual activity. Can you verify?",
        "Your son had an accident. He gave us this number. We need 20000 for treatment now.",
        "This is telecom department. Your number flagged for suspicious activity. Need verification.",
        "Ma'am I am calling from income tax office. You have a pending demand notice.",
        "Aapke bete ka naam hai is case mein. Settlement discuss karna hai.",
        "I am from TRAI. Your sim will be disconnected in 2 hours for misuse.",
        "Your boss asked me to collect the payment for the client. Please transfer 10000.",
        "I am your neighbour's friend. She asked me to collect money for the building fund.",
    ],
    "trust_building": [
        "I've been following your profile. You seem like a genuine person. Can we talk about business?",
        "We met at the conference last week. I have an exclusive deal for early investors.",
        "Hi! I am a financial advisor helping middle class families grow their savings risk-free.",
        "Join our community of 50000 successful traders. Free trial for first week.",
        "Aapke jaisi hardworking family ke liye ye plan perfect hai. No risk, pure profit.",
        "I can help you earn from home. Many housewives in our group earn 30000 monthly.",
        "Sir I'm a student and discovered this earning method. Sharing because it helped me a lot.",
        "Brother I used to be in debt too. This changed my life. Let me show you.",
    ],
    "urgency_disguised": [
        "Limited seats left for this workshop. Registration closing tonight. Only 500 entry fee.",
        "Last 3 hours remaining for early bird offer. After this price doubles.",
        "Your subscription is about to expire. Renew within 24 hours to keep your data.",
        "Seat reserved for you in our premium batch. Confirm by 8 PM today.",
        "Offer valid only till midnight. After that normal pricing applies. Don't miss out.",
        "Aaj last day hai registration ka. Kal se double fee lagegi.",
        "Early investor discount ending soon. Current price 1000, tomorrow it will be 5000.",
        "Your coupon code expires in 1 hour. Use it now to get 90% discount.",
    ],
    "credential_harvest": [
        "Your email storage is 95% full. Click here to upgrade free of charge.",
        "Someone tried to log into your account. Verify your identity here to secure it.",
        "Your Netflix subscription payment failed. Update billing info to continue watching.",
        "We detected a login from Russia on your account. Change password immediately here.",
        "Aapka Instagram account compromise ho sakta hai. Ye link pe jakke secure karo.",
        "Your iCloud photos may be shared publicly. Tap link to check privacy settings.",
        "Account deactivation notice: Verify your phone number within 48 hours.",
        "Your Google Drive sharing settings have been changed. Review access permissions now.",
    ],
}

BORDERLINE_BENIGN = [
    "I got a call from someone claiming to be from the bank. I hung up and called the bank directly.",
    "Ek suspicious message aaya tha mujhe. Don't click unknown links everyone.",
    "My friend got scammed online. Lost 10000. Be careful with UPI payments.",
    "That investment scheme turned out to be fraud. Police complaint filed.",
    "Yaar koi phone pe bol raha tha CBI se hun. Obviously fake tha.",
    "Got another spam call about KYC update. Blocked the number.",
    "Someone sent a lottery winning message. Obviously scam hai. Delete karo.",
    "Bank ne warning di hai fake calls ke baare mein. Stay alert.",
    "WhatsApp pe virus wali link aa rahi thi. Group se nikal diya sender ko.",
    "My colleague warned me about a Ponzi scheme some agents are pushing.",
    "Mere account se unauthorized transaction hua. Bank se baat ki, reversed ho gaya.",
    "That loan app was charging 100% interest. RBI ne ban kar diya ab.",
    "Ek crypto scheme mein paise doobe mere dost ke. Stay away from such things.",
    "The customer care number on Google was fake. Always use official app contacts.",
    "I reported a phishing email to my IT team. They sent an alert to everyone.",
    "Investigation chal rahi hai online fraud ki. Police ne 5 logon ko pakda.",
    "News mein dekha digital arrest scam badh raha hai. Family ko bata diya.",
    "Mummy ko bataya OTP share mat karo kisi ke saath bhi. Important hai.",
    "Refund aa gaya Amazon se normally. Kisi ne bola tha scam hai but legit tha.",
    "UPI pe wrong person ko 1000 bhej diya galti se. Bank se reverse karaya.",
]


def generate_training_data(
    samples_per_category: int = 50,
    benign_ratio: float = 0.45,
    output_path: str = str(OUTPUT_PATH),
) -> int:
    all_samples: List[dict] = []

    for category, templates in SCAM_TEMPLATES.items():
        for i in range(samples_per_category):
            template = random.choice(templates)
            text = _augment_text(template)
            all_samples.append({
                "text": text,
                "label": 1,
                "scam_category": category,
            })

    for category, templates in SUBTLE_SCAM_TEMPLATES.items():
        n_subtle = max(samples_per_category // 3, 8)
        for i in range(n_subtle):
            template = random.choice(templates)
            text = _augment_text(template, intensity=0.3)
            all_samples.append({
                "text": text,
                "label": 1,
                "scam_category": f"subtle_{category}",
            })

    n_scam = len(all_samples)

    n_benign = int(n_scam * benign_ratio / (1 - benign_ratio))
    n_adversarial = min(len(ADVERSARIAL_BENIGN) * 3, n_benign // 3)
    n_borderline = min(len(BORDERLINE_BENIGN) * 3, n_benign // 5)
    n_regular = n_benign - n_adversarial - n_borderline

    for i in range(n_regular):
        template = random.choice(BENIGN_MESSAGES)
        text = _augment_text(template, is_scam=False)
        all_samples.append({
            "text": text,
            "label": 0,
            "scam_category": "none",
        })

    for i in range(n_adversarial):
        template = random.choice(ADVERSARIAL_BENIGN)
        text = _augment_text(template, is_scam=False, intensity=0.2)
        all_samples.append({
            "text": text,
            "label": 0,
            "scam_category": "none_adversarial",
        })

    for i in range(n_borderline):
        template = random.choice(BORDERLINE_BENIGN)
        text = _augment_text(template, is_scam=False, intensity=0.15)
        all_samples.append({
            "text": text,
            "label": 0,
            "scam_category": "none_borderline",
        })

    random.shuffle(all_samples)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        for sample in all_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")

    logger.info(
        "Generated %d training samples (%d scam, %d benign) -> %s",
        len(all_samples), n_scam, len(all_samples) - n_scam, output_path,
    )
    return len(all_samples)


_NAMES = ["Sharma", "Verma", "Singh", "Kumar", "Patel", "Khan", "Gupta", "Reddy"]
_PHONES = ["9876543210", "8765432109", "7654321098", "9988776655", "8899776655"]
_LINKS = [
    "http://bit.ly/update-kyc",
    "https://secure-verify.in/kyc",
    "http://bank-verify.co/login",
    "https://claim-prize.net/win",
    "http://refund-process.site/claim",
]


def _augment_text(text: str, is_scam: bool = True, intensity: float = 1.0) -> str:
    text = text.replace("{name}", random.choice(_NAMES))
    text = text.replace("{phone}", random.choice(_PHONES))
    text = text.replace("{link}", random.choice(_LINKS))

    if random.random() < 0.15 * intensity:
        text = text.upper()
    elif random.random() < 0.1:
        text = text.lower()

    if random.random() < 0.25 * intensity:
        text = _add_typo(text)

    if random.random() < 0.2:
        text = _inject_filler(text)

    if is_scam and random.random() < 0.25 * intensity:
        prefixes = [
            "URGENT: ", "WARNING: ", "ALERT: ", "IMPORTANT: ",
            "FINAL NOTICE: ", "ATTENTION: ", "IMMEDIATE ACTION: ",
        ]
        text = random.choice(prefixes) + text

    if is_scam and random.random() < 0.2 * intensity:
        suffixes = [
            " Act now!", " Don't delay!", " Time is running out!",
            " Jaldi karo!", " Abhi response karo!", " Last chance!",
            " Reply immediately.", " This is your final warning.",
        ]
        text += random.choice(suffixes)

    if random.random() < 0.15:
        words = text.split()
        if len(words) > 4:
            cut = random.randint(len(words) // 3, len(words) - 1)
            text = " ".join(words[:cut])

    if random.random() < 0.1:
        text = text + " " + text.split(".")[0] if "." in text else text

    return text.strip()


def _add_typo(text: str) -> str:
    if len(text) < 5:
        return text
    words = text.split()
    if not words:
        return text
    idx = random.randint(0, len(words) - 1)
    word = words[idx]
    if len(word) < 3:
        return text

    op = random.choice(["swap", "delete", "duplicate"])
    pos = random.randint(1, len(word) - 2)
    if op == "swap" and pos < len(word) - 1:
        word = word[:pos] + word[pos + 1] + word[pos] + word[pos + 2 :]
    elif op == "delete":
        word = word[:pos] + word[pos + 1 :]
    elif op == "duplicate":
        word = word[:pos] + word[pos] + word[pos:]
    words[idx] = word
    return " ".join(words)


_FILLER_WORDS = [
    "actually", "basically", "like", "you know", "well",
    "so", "anyway", "right", "okay", "I mean",
    "dekho", "matlab", "waise", "toh", "acha",
]


def _inject_filler(text: str) -> str:
    words = text.split()
    if len(words) < 4:
        return text
    pos = random.randint(1, len(words) - 1)
    filler = random.choice(_FILLER_WORDS)
    words.insert(pos, filler)
    return " ".join(words)


if __name__ == "__main__":
    n = generate_training_data(samples_per_category=80)
    print(f"Generated {n} training samples")
