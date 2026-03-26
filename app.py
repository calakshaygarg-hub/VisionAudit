import streamlit as st
import pdfplumber
import imagehash
from PIL import Image
import pandas as pd
from supabase import create_client, Client
import io

# --- 1. SECURE CONNECTION (Using Streamlit Secrets) ---
URL = st.secrets["SUPABASE_URL"]
KEY = st.secrets["SUPABASE_KEY"]
supabase: Client = create_client(URL, KEY)

# --- 2. SECURITY CHECK (NEW) ---
def check_password():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False

    if not st.session_state["authenticated"]:
        st.title("🔐 VisionAudit Secure Login")
        password = st.text_input("Enter Auditor Access Key", type="password")
        if st.button("Login"):
            if password == "Audit2026!": # This is your password
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                st.error("Access Denied.")
        return False
    return True

if not check_password():
    st.stop()

# --- 3. MAIN INTERFACE ---
st.set_page_config(page_title="VisionAudit Cloud", layout="wide")
st.title("🔍 VisionAudit: Forensic Cloud Vault")

st.sidebar.header("Audit Settings")
case_name = st.sidebar.text_input("Case Reference / Client", "General Audit")
sensitivity = st.sidebar.slider("Match Sensitivity (0 = Exact)", 0, 15, 2)

uploaded_files = st.sidebar.file_uploader(
    "Upload Invoices (PDF) or Images", 
    type=["pdf", "png", "jpg", "jpeg"], 
    accept_multiple_files=True
)

report_data = []

if uploaded_files:
    for uploaded_file in uploaded_files:
        with st.spinner(f"Analyzing {uploaded_file.name}..."):
            current_file_images = []
            if uploaded_file.type == "application/pdf":
                with pdfplumber.open(uploaded_file) as pdf:
                    for i, page in enumerate(pdf.pages):
                        for img in page.images:
                            try:
                                page_obj = page.crop((img["x0"], img["top"], img["x1"], img["bottom"]))
                                image = page_obj.to_image(resolution=150).original
                                h = str(imagehash.phash(image))
                                current_file_images.append({"name": uploaded_file.name, "img": image, "hash": h})
                            except: continue
            else:
                image = Image.open(uploaded_file)
                h = str(imagehash.phash(image))
                current_file_images.append({"name": uploaded_file.name, "img": image, "hash": h})

            for item in current_file_images:
                response = supabase.table("image_inventory").select("file_name, case_name, image_hash").eq("image_hash", str(item["hash"])).execute()
                matches = [row for row in response.data if row["file_name"] != item["name"]]
                
                if matches:
                    match = matches[0]
                    st.error(f"🚨 ALERT: HISTORICAL MATCH DETECTED")
                    st.write(f"**Current File:** `{item['name']}` matches `{match['file_name']}` from Case: `{match['case_name']}`")
                    st.image(item["img"], width=300)
                    st.divider()

                    report_data.append({
                        "Match Type": "Cloud/Historical",
                        "Current File": item["name"],
                        "Matched With": match["file_name"],
                        "Original Case": match["case_name"]
                    })
                else:
                    supabase.table("image_inventory").insert({
                        "case_name": case_name,
                        "file_name": item["name"],
                        "image_hash": item["hash"]
                    }).execute()

    st.success("Audit Complete. Unique images indexed in Cloud Vault.")

    if report_data:
        df = pd.DataFrame(report_data)
        csv = df.to_csv(index=False).encode('utf-8')
        st.sidebar.download_button("📥 Download Forensic Report", csv, f"Audit_{case_name}.csv", "text/csv")

# --- 4. DANGER ZONE (NEW CLEANUP TOOL) ---
st.sidebar.divider()
st.sidebar.subheader("⚠️ Danger Zone")
if st.sidebar.button("Clear ALL Database Records"):
    supabase.table("image_inventory").delete().neq("id", 0).execute()
    st.sidebar.warning("Cloud Vault has been wiped clean.")
    st.rerun()

if st.sidebar.button("Delete ONLY Current Case"):
    supabase.table("image_inventory").delete().eq("case_name", case_name).execute()
    st.sidebar.info(f"Records for {case_name} deleted.")
    st.rerun()
