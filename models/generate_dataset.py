#!/usr/bin/env python3
"""
Generate a large, diverse synthetic training dataset for ScamIntelli.
Produces ~5000+ unique samples covering Indian scam patterns, prize/lottery,
digital arrest, credential phishing, and adversarial benign messages.
"""
import json
import random
import hashlib
from pathlib import Path

OUTPUT = Path("models/training_data.jsonl")

# ── Prize / Lottery scam templates ───────────────────────────────────────────
PRIZE_LOTTERY = [
    "WON ! You have won some lakh ! Pleaase share your bank account number to proceed !!.",
    "Congratulations! You have won 25 lakh in WhatsApp Lucky Draw! Share bank details to claim.",
    "You are selected for Google Lottery 2024. Claim 50 lakh prize money by paying processing fee.",
    "KBC lottery winner! Pay processing fee of 5000 to claim 1 crore.",
    "You won 10 lakh! Send bank account number and IFSC code to receive prize money.",
    "Dear winner, your mobile number has won Rs. 50,00,000 in our mega draw. Pay GST to claim.",
    "Jio Lucky Draw Winner! You won iPhone 15 Pro + 5 lakh cash. Pay 2999 shipping fee.",
    "Congratulations! Your WhatsApp number selected in international lottery. Prize: $100,000.",
    "Facebook Mega Lucky Draw! You won $500,000. Share passport and bank details immediately.",
    "Aapko lucky draw mein 10 lakh mile hain! Claim karne ke liye 2000 bhejo turant.",
    "Dear customer, your number won bumper prize of 25 lakh. Pay tax amount 5000 to claim now.",
    "ALERT: You won Rs 1 crore in Amazon Lucky Draw. Click link to claim prize money.",
    "Instagram random selection winner! You won 2 lakh. Share UPI ID for direct transfer.",
    "WINNER WINNER! Aapne jeeta hai 5 lakh ka inaam! Bank account share karo abhi.",
    "Google Pay lucky winner! 1 lakh cashback. Submit bank details within 24 hours.",
    "Congratulations! You have been selected as the winner of our annual giveaway. Prize: Rs 15 lakh.",
    "Dear user, you won scratch card prize of Rs 50,000. Pay 500 registration fee.",
    "Paytm Lucky Draw! You won 3 lakh! Share Aadhaar + bank details for verification.",
    "Your email selected in Microsoft Sweepstakes. Prize: $75,000. Reply with personal details.",
    "Aapka mobile number jeeta hai mega jackpot! 1 crore rupaye! Processing fee 10,000 bhejo.",
    "Samsung Galaxy S25 Ultra free! You won in our lucky draw. Pay 1999 delivery charges.",
    "TATA Motors lucky draw winner. You won Nexon EV + 10 lakh cash. Claim within 48 hours.",
    "Dear winner you won cash prize of 7 lakh. Transfer GST charges 3500 for processing.",
    "Flipkart Big Billion Day winner! Free laptop + 2 lakh. Pay insurance fee 1500.",
    "You have won 50 lakh in RBI approved lottery scheme. Contact agent with bank details.",
    "Bumper Dhamaka! Aapne jeeta hai 20 lakh ka prize. OTP bhejo verification ke liye.",
    "FREE! You won gold coin + 5 lakh in Diwali mega draw. Pay courier charges 999.",
    "International Lottery Commission: You won €200,000. Send processing documents immediately.",
    "Vodafone lucky draw! Your number won Rs 3,00,000. Registration fee required: Rs 1500.",
    "Special Holi offer winner! Free trip to Goa + 1 lakh cash. Pay booking fee.",
]

DIGITAL_ARREST = [
    "This is Cyber Crime Department. Your Aadhaar has been used for illegal activities. Digital arrest.",
    "I am Inspector Kumar from CBI. Case registered against you. Transfer 50000 to settle now.",
    "Your phone number is linked to money laundering case. Verify now or face arrest immediately.",
    "Cyber crime branch here. Your bank account being used for fraud. Stay on call. Do not disconnect.",
    "This is Delhi Police Cyber Cell. FIR filed against your Aadhaar. Pay fine immediately.",
    "Supreme Court order against you. Digital arrest warrant issued. Do not cut the call ever.",
    "I am calling from Enforcement Directorate. Your PAN linked to hawala transactions. Settle now.",
    "NCB calling. Drugs found in parcel booked under your name. Stay on video call for verification.",
    "Sir aapke khilaf arrest warrant jari ho gaya hai. Abhi settlement karo warna jail jayenge.",
    "Yeh CBI ka official call hai. Aapka Aadhaar se 50 fake accounts khule hain. Serious matter.",
    "Aapke phone number se fraud hua hai. 2 ghante mein police aayegi ghar pe. Pay settlement.",
    "Digital arrest under section 420. Bail ke liye 1 lakh transfer karo turant nahi toh jail.",
    "Mumbai Police calling. Your name connected to terrorism funding case. Comply or face arrest.",
    "FEMA violation detected on your account. Enforcement Directorate will freeze all your assets.",
    "Narcotics Control Bureau. Parcel with drugs traced to your Aadhaar. Video call for interrogation.",
    "Income Tax raid notice. You have undisclosed income of 50 lakh. Pay penalty or face prosecution.",
    "This is from TRAI. Your mobile number used for illegal calls. SIM deactivation in 4 hours.",
    "Customs department. International parcel with illegal items under your PAN card. Pay clearance fee.",
    "Central Bureau of Investigation. Case number 2024/CR/4521 filed. Digital hearing on Skype now.",
    "Aapke naam pe FIR darj ho gayi hai. Supreme Court ka order hai. Abhi paise transfer karo.",
]

KYC_PHISHING = [
    "Dear customer, your KYC is pending. Update now or account will be blocked: http://bit.ly/kyc-update",
    "Your SBI account will be suspended in 24 hours. Click link to verify KYC immediately.",
    "URGENT: Complete KYC verification for Paytm wallet or lose all balance. Visit secure-verify.in.",
    "RBI notification: KYC update mandatory for all bank accounts. Failure will result in freeze.",
    "Aapka bank account block ho jayega agar KYC update nahi kiya 24 hours mein. Click karo link.",
    "Dear user your PAN card not linked to bank. Complete verification now to avoid suspension.",
    "ICICI Bank: Your account KYC expired on 15th. Update at link to avoid deactivation and freeze.",
    "Aapka Aadhaar link nahi hai bank se. Abhi karo nahi toh account permanently band ho jayega.",
    "HDFC alert: Your netbanking access will be blocked. Update Aadhaar for re-verification today.",
    "SBI alert: Your debit card will be suspended. Complete e-KYC at http://sbi-verify.top/kyc.",
    "Kotak Mahindra Bank: Mandatory KYC update. Click here or face permanent account deactivation.",
    "Axis Bank: Your mobile number not verified. Update KYC or account freeze in 48 hours.",
    "PNB alert: Complete Aadhaar seeding or your pension/salary will be held. Verify immediately.",
    "URGENT: Your airtel payment bank KYC expired. Wallet will be frozen. Update now at this link.",
    "Your EPF account KYC pending. Update PAN + Aadhaar or withdrawal will be blocked.",
]

INVESTMENT_FRAUD = [
    "Invest 10000 today and earn 1 lakh in 30 days. Guaranteed 1000% returns!",
    "Join our WhatsApp group for daily stock tips. 500% returns guaranteed. Limited seats.",
    "SEBI registered investment advisor here. Minimum 50% monthly returns on your capital.",
    "Trading signals group join karo. Daily 10000 profit pakka hai. Risk free guaranteed.",
    "Crypto mining pool opportunity. Invest 5000, earn 50000 per month passive income.",
    "IPO allotment guaranteed. Transfer registration fee of 2000 rupees for premium access.",
    "Share market mein paisa double karo in 7 days. 100% safe government backed investment.",
    "Binary options trading platform. Risk free returns guaranteed. Join now. Zero loss policy.",
    "Put 25000 in our AI trading bot. Average daily return 5000. Withdraw anytime guaranteed.",
    "Forex signals VIP group. Monthly returns 200%. Join with 10000 deposit. Money back guarantee.",
    "Real estate investment tokenized. 50% annual returns. Minimum investment only 15000.",
    "MLM networking opportunity. Earn 1 lakh monthly. Just recruit 5 people. Passive income forever.",
    "Bitcoin multiplier! Send 0.1 BTC, receive 1 BTC back within 24 hours. Verified platform.",
    "Aaj hi invest karo 50000. 3 mahine mein 5 lakh milega guaranteed. No risk at all.",
    "Stock market advisory free trial. After trial, guaranteed 3x returns. Registration 3000.",
]

JOB_SCAM = [
    "Work from home job! Earn 50000 monthly. Just pay 500 registration fee to start.",
    "Amazon hiring data entry operators urgently. No experience needed. Apply with 1000 fee.",
    "Part time typing job from home. 2000 per day income. Registration charges only 1000.",
    "Flipkart product review job. Earn per review. Pay training fee of 2000 first to start.",
    "Online task completion job. Daily income 5000 guaranteed. Deposit 2000 to start earning.",
    "Telegram group join karo. Like and subscribe karke 500 daily kamao. Very simple work.",
    "Government job vacancy! Pay 3000 for form processing fee and get guaranteed selection.",
    "International company hiring Indians. Work from mobile phone. Registration fee 1500 only.",
    "YouTube video watching job. 100 per video. Earn 3000 daily. Pay activation fee 500 first.",
    "Copy paste job from home. Monthly 40000 income. Training charges 2500 refundable.",
    "Meesho reselling job. Earn 1 lakh monthly. Join premium seller program, fee 3000.",
    "Survey completion job. 200 per survey. Complete 20 daily = 4000. Registration 800.",
    "Google hiring work from home position. Salary 80000/month. Apply with verification fee 5000.",
    "Aap ghar baithe 30000 kama sakte hain. Bas 1500 registration fee do aur shuru karo.",
    "Data labeling AI job. Earn $50/day. Pay $20 software activation fee to begin working.",
]

ROMANCE_SCAM = [
    "I am a US military officer deployed overseas. I have gold stuck in customs. Need money to release it.",
    "My gift for you is stuck at Indian customs. Pay 5000 duty charges to receive this special package.",
    "I love you darling. Send me money for flight ticket to finally meet you in person. 25000 only.",
    "I am stuck abroad with a medical emergency. Please send 20000 urgent. I will repay double.",
    "My inheritance is locked in a foreign bank. Help me with 10000 and I'll share 50% with you.",
    "Baby I want to send you expensive gift from London. Pay customs clearance fee of 8000.",
    "I am oil rig engineer. My salary is stuck because of banking issues. Please help with 15000.",
    "Jaan mujhe visa ke liye paise chahiye urgently. 30000 bhejo please. I promise to come see you.",
    "I am UN diplomat. I have $2 million in a trunk. Need 50000 for clearance to share half with you.",
    "My crypto wallet with $500K is locked. Send 10000 INR for verification fee. I'll send 1 lakh back.",
]

TECH_SUPPORT = [
    "Your computer has been infected with dangerous virus. Call Microsoft certified support at 1800XXXXXX.",
    "Windows security critical alert! Your system compromised by hackers. Install AnyDesk now for fix.",
    "Apple ID locked due to suspicious activity from foreign country. Call support immediately. Urgent.",
    "Your antivirus subscription expired today. Renew now or lose all your personal data permanently.",
    "Firewall breach detected on your network. Download TeamViewer for remote fix by certified engineer.",
    "Microsoft calling. Your Windows license expired. Pay 5000 for lifetime renewal immediately.",
    "System compromised by hackers who are accessing your bank right now. Install remote access software.",
    "Your Amazon Prime membership auto-renewing for Rs 15000. Call to cancel or it will be charged.",
    "Norton antivirus alert! 47 threats found. Your banking data at risk. Call helpline now. Urgent.",
    "Aapke computer mein Trojan virus hai. Turant call karo nahi toh saara data chori ho jayega.",
]

CUSTOMS_PARCEL = [
    "Your parcel seized at customs. Drugs found inside. Pay 10000 clearance fee or face arrest.",
    "DHL courier detained at Mumbai airport. Import duty charges pending. Pay to release your parcel.",
    "FedEx package with illegal contents found under your name. Call customs officer immediately.",
    "International parcel with contraband detected by scanning. Legal action if not cleared in 24 hours.",
    "Aapka parcel customs mein ruka hai. 15000 duty charges bhejo nahi toh police case hoga.",
    "Courier seized by narcotics department. Pay fine of 25000 or face serious criminal charges.",
    "Amazon international order held at Delhi customs. Pay import duty via link to release package.",
    "Parcel from London with high value items detained. Contact customs officer to avoid legal action.",
    "Your DHL shipment #DHL782934 flagged for suspicious contents. Settlement required immediately.",
    "Air India cargo notification: Package under your PAN held. Customs duty 12000 pending.",
]

LOAN_FRAUD = [
    "Pre-approved personal loan of 5 lakh just for you! Just pay 2000 processing fee to start.",
    "Instant loan approved! Low CIBIL score no problem at all. Pay documentation charges 3000 only.",
    "Loan disbursement of 10 lakh ready. Transfer GST charges of 3000 to release the full amount.",
    "5 minute instant loan approval. No documents needed at all. Registration fee only 1500 rupees.",
    "Aapka personal loan of 8 lakh approve ho gaya hai. Processing fee 5000 transfer karo to release.",
    "Bank pre-approved loan offer! Zero interest for 6 months! Pay advance EMI to activate now.",
    "Zero interest business loan for government employees. Just pay 1000 stamp duty charges.",
    "Loan of 10 lakh fully sanctioned today. Pay insurance charges of 4000 to proceed with disbursal.",
    "Your credit score qualifies for 15 lakh loan at 0% interest! Fast approval. Fee: Rs 2500.",
    "Mudra loan approved by PM scheme. 3 lakh at 0% interest. Processing charges 1500. Apply now!",
]

REFUND_SCAM = [
    "Your refund of Rs 15,000 is pending processing. Click this link to verify and receive it today.",
    "Excess amount of 5000 accidentally credited to your account. Return via UPI immediately please.",
    "Income tax refund of 8000 available for you. Enter bank details and Aadhaar to receive it now.",
    "Insurance claim refund of 25000 ready for you. Pay processing fee of only 500 to get it.",
    "Aapka refund bank mein aa gaya hai. Verify karne ke liye apna OTP bhejo. Turant milega.",
    "Wrong transfer of 25000 went to your account by mistake. Please return immediately via UPI.",
    "Order cancelled. Refund initiated for your order. Click link to verify your bank account details.",
    "Government LPG subsidy refund Rs 3000 pending. Enter Aadhaar and bank details to receive.",
    "Your Flipkart return refund stuck. Verify payment method to receive Rs 4500 refund immediately.",
    "Railway ticket cancellation refund pending Rs 1200. Enter bank details for instant credit.",
]

CRYPTO_SCAM = [
    "Bitcoin investment opportunity! 10x guaranteed returns in 30 days. Zero risk platform.",
    "Join our premium crypto trading group. Daily profitable signals. Initial deposit 5000 only.",
    "FREE crypto airdrop! Connect your wallet at this verified link to claim free tokens now.",
    "NFT presale exclusive access for you! Mint now before price goes up 100x. Limited time.",
    "Staking rewards of 500% APY guaranteed. Deposit your crypto now and start earning today.",
    "DeFi yield farming opportunity. Put 10000 get 100000 in one month. Verified smart contract.",
    "New Elon Musk backed token launching! Early investors guaranteed 1000% returns.",
    "Crypto recovery service. We can recover your lost Bitcoin. Pay 10000 consultation fee first.",
    "Binance special promotion! Deposit 1 BTC, get 3 BTC back instantly. Verified by Binance CEO.",
    "Airdrop alert! Free 10000 USDT for early adopters. Connect wallet and claim before midnight!",
]

SEXTORTION = [
    "I have your private video recorded from webcam. Pay 50000 or I share with all your contacts.",
    "Your private photos have been recorded from video call. Send money or I post them online.",
    "Video call recorded. Pay 20000 within 2 hours or I send recording to your entire family.",
    "Adult website visit history recorded. Your contacts list obtained. Pay 30000 now or face shame.",
    "Tumhara video mere paas hai. 30000 do nahi toh viral karunga sabko bhejunga. Last warning.",
    "Pay to delete your private content. 10000 is last chance. After that no mercy. Timer running.",
    "I hacked your webcam. I have 3 videos. Pay 1 BTC or everything goes to your employer.",
    "Your WhatsApp video call screen recorded. Beautiful evidence. Transfer money or face consequences.",
]

SIM_SWAP = [
    "Your SIM needs urgent upgrade from 4G to 5G technology. Share OTP for activation now.",
    "Telecom verification required urgently. Your SIM will be permanently deactivated in 2 hours.",
    "Jio 5G upgrade offer! Share verification code sent to your number to activate free 5G.",
    "Your mobile number is being ported by someone. Share OTP to stop unauthorized transfer.",
    "SIM blocked due to KYC expiry issue. Share Aadhaar OTP to reactivate your number today.",
    "Free 5G SIM upgrade available! Just verify with OTP sent to your number. Valid till today.",
    "Airtel: Your SIM will be deactivated in 4 hours. Share verification OTP to prevent it.",
    "BSNL notification: Your SIM flagged for misuse. Verify identity by sharing OTP immediately.",
]

QR_CODE = [
    "I am interested buyer for your OLX product. Scan this QR code to receive payment of 5000.",
    "Scan QR code to get your OLX payment directly. Amount will be 8000 credited instantly.",
    "Payment via QR code for your product listing. Scan to receive money to your bank account.",
    "Refund via QR code available. Scan to get 3000 refund back to your account instantly.",
    "Main buyer hun. QR scan karo payment aa jayega 10000 turant. Very simple and fast.",
    "PhonePe QR code for receiving amount. Please scan and money will be credited to you.",
    "Google Pay QR payment. Scan to receive Rs 12000 for the item you listed on marketplace.",
    "Army officer interested in your car. Sending advance payment via QR. Please scan to receive.",
]

# ── Benign (legitimate) messages ─────────────────────────────────────────────
BENIGN = [
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
    "I'll be working from home tomorrow. No office.",
    "Grocery list bhej do, main market ja raha hun.",
    "Netflix pe naya show dekha? Kaafi accha hai.",
    "Flight confirmed for next Friday at 6 AM. Terminal 3.",
    "Doctor appointment hai 11 baje. Thoda late aaunga.",
    "Rent transfer kar diya hai. Check karo bank mein.",
    "Parking mein gaadi laga di. 5th floor pe aa jao.",
    "Wifi password kya hai? Connect nahi ho raha.",
    "Tea ya coffee? Main canteen ja raha hun.",
    "Resume update kar liya. Review kar doge please?",
    "Sharma ji ne invite kiya hai dinner pe. Chalein?",
    "AC ki service karwani hai. Technician ka number hai?",
    "Mummy ne poha banaya hai. Aake kha lo breakfast.",
    "Class cancel hai aaj. Professor sick leave pe hain.",
    "Cab book kar lo. 8 baje nikalna hai sharp.",
    "Cousins aa rahe hain Diwali pe. Room ready karna padega.",
    "Match dekh rahe ho? India bowling kar raha hai abhi.",
    "Presentation acchi gayi aaj. Boss ne appreciate kiya!",
    "Headache ho raha hai. Koi medicine hai tumhare paas?",
    "Library mein hun. 2 baje tak free ho jaunga.",
    "Swiggy se order karna hai? Kya khayenge?",
    "New phone lena hai. Budget 20000 hai maximum.",
    "Parking full hai mall mein. Kisi aur jagah chalte hain.",
    "Exam next week hai. Notes share karo please urgently.",
    "Ruko 5 minute, abhi aa raha hun. Almost there.",
    "Aaj kaafi thak gaya. Early sleep karunga tonight.",
    "Weekend pe Goa plan karein? Tickets saste hain.",
    "Kal interview hai company mein. Wish me luck!",
    "Electricity bill pay kar do online. Due date kal hai.",
    "I shared the meeting notes in Slack channel. Check.",
    "The weather is really nice today for a walk outside.",
    "Can you pick up milk on your way home tonight?",
    "I just submitted my tax returns for this FY.",
    "The kids have a school annual event next Wednesday.",
    "Thanks for the birthday wishes everyone! Grateful.",
    "Just got back from vacation. So much work pending now.",
    "Team outing plan karte hain is month end. Ideas?",
    "Ek aur chai pi lete hain. Thandi ho rahi hai bahar.",
    "Temple jaana hai Sunday. Subah 7 baje niklenge.",
    "IPL ka match dekho aaj raat. Bahut exciting final.",
    "Bhai kal lunch pe chalein? Naye restaurant khula hai.",
    "Kab aa rahe ho tum? Main wait kar raha hun.",
    "Arey yaar, kal ka homework kar liya tune?",
    "Office mein aaj bahut kaam hai, late ho jaunga.",
    "Mummy ne chai banayi hai, aa jao fresh wali.",
    "Bhai tera charger dede 5 min ke liye, mera dead hai.",
    "Subah jaldi uthna hai kal. Alarm laga lena please.",
    "Main abhi market mein hun. Kuch chahiye toh batao.",
    "Aaj bahut thak gaya yaar. Sone ja raha hun now.",
    "Tune woh video dekhi WhatsApp pe? Bahut funny thi.",
    "Bhai pizza order karte hain aaj treat meri.",
    "Kal exam hai subah, padhai kar raha hun abhi.",
    "Mumma ka phone aaya, unki tabiyat theek nahi hai.",
    "Ghar pe paani nahi aa raha, plumber ko call kar.",
    "Bhai paise wapas karde, 200 the mere jo diye the.",
    "Shopping karne jaana hai, saath chalogi kya?",
    "Train late hai, 30 minute extra wait karna padega.",
    "Kal salary aa gayi, party dene ka time aa gaya!",
    "Doctor ke paas jaana hai, appointment le li subah ki.",
    "Main ghar pahunch gaya safely, don't worry about me.",
    "Dinner ready hai, table pe aa jao everyone.",
    "Kal cricket khelne chalein? Ground book kar leta hun.",
    "Papa se permission le li, trip pe ja sakte hain!",
    "Aaj bahut garmi hai, ice cream khaate hain chalo.",
    "How are you doing? Long time no see! Miss you.",
    "Please send the invoice for last month's order asap.",
    "The client meeting went well today. They liked proposal.",
    "Let's catch up over coffee this weekend. My treat.",
    "I'm running late, please start without me today.",
    "Just finished a great workout at the gym. Feeling good.",
    "Do you want to carpool tomorrow morning to save fuel?",
    "The deadline has been extended by one full week.",
    "Happy anniversary to you both! Many more years together!",
    "What time does the store close today evening?",
    "Let me know once you've reviewed the pull request.",
    "The food at that place was amazing! Must visit again.",
    "Can you water my plants while I'm away on trip?",
    "I need to renew my passport before the international trip.",
    "Thanks for picking me up from the airport yesterday!",
    "The internet is so slow today, can barely stream video.",
    "Aaj meri anniversary hai. Dinner plan kiya hai.",
    "Birthday party mein kya gift le jaayein? Ideas?",
    "Weekend pe family picnic plan hai. Sabko batao.",
    "Kal Sunday hai. Ghar pe chill karte hain.",
    "Garden mein naye phool laga diye hain. Bahut sundar.",
]

ADVERSARIAL_BENIGN = [
    "I need to update my KYC at the bank branch tomorrow morning as scheduled.",
    "Just transferred 5000 to mom's account for groceries. Normal family transfer.",
    "My PAN card arrived today. Linked it with bank account at the branch.",
    "Police uncle came for routine address verification at our house. Standard process.",
    "Got my income tax refund today! 8000 rupees credited normally to bank account.",
    "I won the college sports competition! Got 10000 cash prize from dean.",
    "Doctor said the surgery will cost 50000. Need to arrange funds from savings.",
    "Bank app is down, can't check OTP for my own transaction. Frustrating.",
    "Aadhaar card update ho gaya at center. Biometrics bhi de diye normally.",
    "SBI branch mein 2 ghante laga KYC karane mein. Line bahut lambi thi aaj.",
    "Papa ne 1 lakh fixed deposit karwaya hai. Good interest rate mil raha.",
    "CBI raid ki news dekhi TV pe? Office ke paas hua kuch yesterday.",
    "New SIM card activate karna hai. Store pe jaana padega for verification.",
    "Paytm se wallet top up kar liya. 2000 daale hain for shopping.",
    "Cyber crime awareness seminar hai college mein next week. Should attend.",
    "UPI se payment kiya dukaan pe normally. 500 rupees kata for groceries.",
    "Mera Amazon refund aa gaya normally. 1500 back in account.",
    "Investment advisor se mila aaj. SIP start karne ka soch raha hun seriously.",
    "Mutual fund mein 10000 per month invest kar raha hun ab se. Long term plan.",
    "Bank se legitimate loan approve ho gaya. 5 lakh personal loan at 10.5%.",
    "Job interview clear ho gaya! Offer letter aayega next week. Happy!",
    "Salary credited normally! 50000 in account after tax deduction.",
    "SEBI guidelines change hui hain recently. New rules for mutual funds.",
    "Stock market mein aaj bahut crash hua unfortunately. Portfolio down 15%.",
    "Google Pay se electricity bill pay kiya normally. 3000 tha this month.",
    "Customs duty pay karna pada international Amazon order pe. 2000 extra laga.",
    "My old laptop sold on OLX successfully. Got 15000 from genuine buyer.",
    "Bank manager se meeting discuss ki home loan options for new flat.",
    "Aadhaar OTP aaya mobile pe. Branch walon ne maanga tha for legitimate KYC.",
    "FIR file kiya hai chain snatching incident ka. Police station gaye correctly.",
    "Income tax return file kiya online portal pe. Refund aayega 3 weeks mein.",
    "SIM upgrade kiya 5G at official Jio store. Free mein ho gaya.",
    "Court mein ongoing case chal raha hai property dispute ka. Lawyer fees bahut.",
    "Credit card bill 25000 aaya is month. Pay karna padega before due date.",
    "Insurance premium due hai next month. 12000 pay karna hai for health plan.",
    "Passport renewal ke liye official appointment liya hai. Documents ready hain.",
    "School fees 30000 pay karni hai next installment. March mein due.",
    "ATM se 10000 nikale for cash payment to electrician. Normal withdrawal.",
    "CIBIL score check kiya online. 750 aa raha hai, quite good.",
    "Mummy ka medical bill 40000 aaya. Insurance se claim karenge legitimately.",
    "Train ticket book kiya IRCTC se. UPI payment 1200 normal transaction.",
    "Friend asked for 5000 urgently for emergency. Sent via Google Pay.",
    "Just completed Aadhaar verification at official telecom store for 5G upgrade.",
    "Police called about minor traffic violation challan. Need to pay fine online.",
    "Invested in IPO through my Zerodha account last month. Got allotment!",
    "My wallet was stolen yesterday at market. Blocked all cards immediately.",
    "Account verification done at branch by bank manager. Address proof submitted.",
    "I went to bank to report a suspicious transaction. They reversed it.",
    "Our company is genuinely hiring data entry operators. Send resume to HR email.",
    "Got security alert from bank about new device login. Changed password safely.",
]

BORDERLINE_BENIGN = [
    "I got a call from someone claiming to be from the bank. I hung up and called bank directly.",
    "Ek suspicious message aaya tha mujhe. Don't click on unknown links everyone! Stay safe.",
    "My friend got scammed online unfortunately. Lost 10000. Be careful with UPI payments everyone.",
    "That investment scheme turned out to be fraud. Police complaint filed against organizers.",
    "Yaar koi phone pe bol raha tha CBI se hun. Obviously fake tha. Blocked the number.",
    "Got another spam call about KYC update. Blocked the number immediately.",
    "Someone sent a lottery winning message again. Obviously scam hai. Delete karo immediately.",
    "Bank ne official warning di hai fake calls ke baare mein. Stay alert everyone.",
    "WhatsApp pe virus wali link aa rahi thi. Group se nikal diya sender ko.",
    "Colleague warned about a Ponzi scheme some agents are pushing in office area.",
    "Mere account se unauthorized transaction detected hua. Bank se baat ki, reversed successfully.",
    "That sketchy loan app was charging 100% interest! RBI ne ban kar diya ab thankfully.",
    "News mein dekha digital arrest scam badh raha hai. Family ko bata diya for awareness.",
    "Mummy ko bataya OTP share mat karo kisi ke saath bhi. Very important safety tip.",
    "Refund aa gaya Amazon se normally. Someone said it was scam but it was legit.",
    "UPI pe wrong person ko 1000 bhej diya galti se. Bank helped reverse it.",
    "I reported a phishing email to my company IT team. They sent alert to everyone.",
    "Investigation chal rahi hai online fraud ring ki. Police ne 5 logon ko pakda.",
    "Saw news about new crypto scam targeting WhatsApp groups. Be careful everyone.",
    "My bank called from official number about suspicious login. Verified and changed password.",
]


def _names():
    return ["Sharma", "Verma", "Singh", "Kumar", "Patel", "Khan", "Gupta", "Reddy", "Chauhan", "Mishra", "Yadav", "Joshi"]

def _augment(text, is_scam=True, intensity=1.0):
    text = text.replace("{name}", random.choice(_names()))
    text = text.replace("{phone}", f"{random.choice([7,8,9])}{random.randint(100000000,999999999)}")
    text = text.replace("{link}", random.choice([
        "http://bit.ly/verify-now", "https://secure-bank.top/kyc",
        "http://claim-prize.net/win", "https://refund-process.site",
        "http://kyc-update.co/verify", "https://bank-secure.xyz/login",
    ]))
    r = random.random()
    if r < 0.12 * intensity:
        text = text.upper()
    elif r < 0.18:
        text = text.lower()
    # Add random word-level noise for uniqueness
    if random.random() < 0.30:
        words = text.split()
        if len(words) > 3:
            idx = random.randint(1, len(words)-1)
            w = words[idx]
            if len(w) > 3:
                pos = random.randint(1, len(w)-2)
                w = w[:pos] + w[pos]*random.randint(1,2) + w[pos+1:]
                words[idx] = w
            text = " ".join(words)
    # Swap random word positions for more uniqueness
    if random.random() < 0.25:
        words = text.split()
        if len(words) > 5:
            i, j = random.sample(range(1, len(words)-1), 2)
            words[i], words[j] = words[j], words[i]
            text = " ".join(words)
    # Random punctuation variation
    if random.random() < 0.20:
        text = text.replace(".", random.choice([".", "!", "..", "..."]))
    if random.random() < 0.15:
        text = text.replace(",", random.choice([",", " -", ";", " "]))
    if is_scam and random.random() < 0.18 * intensity:
        text = random.choice(["URGENT: ","WARNING: ","ALERT: ","IMPORTANT: ","FINAL NOTICE: ","⚠️ "]) + text
    if is_scam and random.random() < 0.15 * intensity:
        text += random.choice([" Act now!", " Hurry!", " Jaldi karo!", " Don't delay!", " Last chance!", " Time running out!"])
    # Add time/greeting prefix for variety
    if not is_scam and random.random() < 0.30:
        text = random.choice([
            "Hey, ", "Hi! ", "Bhai ", "Yaar ", "Haan ", "Ok so ", "Btw ", "Accha ",
            "Suno ", "Dekho ", "Arey ", "Bro ", "Dude ", "Listen "
        ]) + text
    return text.strip()


def main():
    all_scam_categories = {
        "prize_lottery": PRIZE_LOTTERY,
        "digital_arrest": DIGITAL_ARREST,
        "kyc_phishing": KYC_PHISHING,
        "investment_fraud": INVESTMENT_FRAUD,
        "job_scam": JOB_SCAM,
        "romance_scam": ROMANCE_SCAM,
        "tech_support": TECH_SUPPORT,
        "customs_parcel": CUSTOMS_PARCEL,
        "loan_fraud": LOAN_FRAUD,
        "refund_scam": REFUND_SCAM,
        "crypto_scam": CRYPTO_SCAM,
        "sextortion": SEXTORTION,
        "sim_swap": SIM_SWAP,
        "qr_code_scam": QR_CODE,
    }

    samples = []
    seen = set()
    def add(text, label, cat="none"):
        h = hashlib.md5(text.encode()).hexdigest()
        if h in seen:
            return
        seen.add(h)
        samples.append({"text": text, "label": label, "scam_category": cat})

    # Generate scam samples: 20 augmented variants per template
    for cat, templates in all_scam_categories.items():
        for tmpl in templates:
            add(tmpl, 1, cat)
            for _ in range(19):
                add(_augment(tmpl, True), 1, cat)

    # Generate benign samples to match ~40% total ratio (good balance)
    n_scam = len(samples)
    target_benign = int(n_scam * 0.65)  # ~40% benign of total

    # Regular benign - 45%, Adversarial - 35%, Borderline - 20%
    regular_count = int(target_benign * 0.45)
    adversarial_count = int(target_benign * 0.35)
    borderline_count = target_benign - regular_count - adversarial_count

    for _ in range(regular_count):
        add(_augment(random.choice(BENIGN), False, 0.3), 0, "none")
    for _ in range(adversarial_count):
        add(_augment(random.choice(ADVERSARIAL_BENIGN), False, 0.3), 0, "none_adversarial")
    for _ in range(borderline_count):
        add(_augment(random.choice(BORDERLINE_BENIGN), False, 0.3), 0, "none_borderline")

    random.shuffle(samples)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    n_scam_final = sum(1 for s in samples if s["label"] == 1)
    n_benign_final = sum(1 for s in samples if s["label"] == 0)
    print(f"Generated {len(samples)} samples: {n_scam_final} scam, {n_benign_final} benign")
    cats = {}
    for s in samples:
        c = s["scam_category"]
        cats[c] = cats.get(c, 0) + 1
    for c, n in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"  {c}: {n}")

if __name__ == "__main__":
    main()
