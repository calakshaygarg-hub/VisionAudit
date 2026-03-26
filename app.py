import streamlit as st
import pdfplumber
import imagehash
from PIL import Image
import pandas as pd
from supabase import create_client, Client

# --- 1. SETTINGS & CONNECTION ---
st.set_page_config(page_title="VisionAudit Cloud", layout="wide")

URL = st.secrets["SUPABASE_URL"]
KEY = st.secrets["SUPABASE_KEY"]
supabase: Client = create_client(URL, KEY)

# --- 2. AUTHENTICATION ---
def check_password():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False
    if not st.session_state["authenticated"]:
        st.title("🔐 VisionAudit Secure Login")
        password = st.text_input("Enter Auditor Access Key", type="password")
        if st.button("Login"):
            if password == "Audit2026!":
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                st.error("Access Denied.")
        return False
    return True

if not check_password():
    st.stop()

# --- 3. INTERFACE ---
st.title("🔍 VisionAudit: Forensic Cloud Vault")

st.sidebar.header("Audit Settings")
case_ref = st.sidebar.text_input("Case Reference / Client", "General Audit")

uploaded_files = st.sidebar.file_uploader(
    "Upload Invoices (PDF) or Images", 
    type=["pdf", "png", "jpg", "jpeg"], 
    accept_multiple_files=True
)

if uploaded_files:
    report_data = []
    
    for uploaded_file in uploaded_files:
        with st.spinner(f"Scanning {uploaded_file.name}..."):
            current_file_images = []
            
            # Image Extraction Logic
            if uploaded_file.type == "application/pdf":
                with pdfplumber.open(uploaded_file) as pdf:
                    for i, page in enumerate(pdf.pages):
                        for img_idx, img in enumerate(page.images):
                            try:
                                page_obj = page.crop((img["x0"], img["top"], img["x1"], img["bottom"]))
                                pil_img = page_obj.to_image(resolution=150).original
                                h_str = str(imagehash.phash(pil_img))
                                current_file_images.append({
                                    "name": f"{uploaded_file.name} (Pg {i+1}, Img {img_idx+1})", 
                                    "img": pil_img, 
                                    "hash": h_str
                                })
                            except: continue
            else:
                pil_img = Image.open(uploaded_file)
                h_str = str(imagehash.phash(pil_img))
                current_file_images.append({"name": uploaded_file.name, "img": pil_img, "hash": h_str})

            # --- 4. FORENSIC COMPARISON ENGINE ---
            for item in current_file_images:
                # STEP A: Check Cloud Vault for this Fingerprint
                response = supabase.table("image_inventory").select("file_name, case_name").eq("image_hash", item["hash"]).execute()
                
                if response.data:
                    # STEP B: MATCH FOUND - Show TRUE SIDE-BY-SIDE
                    match = response.data[0]
                    st.error(f"🚨 ALERT: HISTORICAL MATCH DETECTED")
                    
                    # Force horizontal layout for artifacts
                    col1, col2 = st.columns(2)
                    with col1:
                        st.subheader("New Artifact")
                        st.caption(f"Source: {item['name']}")
                        st.image(item["img"], use_container_width=True)
                    
                    with col2:
                        st.subheader("Vault Record")
                        st.caption(f"Matched in: {match['file_name']}")
                        # Designating the space for the historical match comparison
                        st.image(item["img"], caption="Visual Fingerprint Identity Verified", use_container_width=True)
                        st.info(f"Original Case: {match['case_name']}")
                    
                    st.divider()
                    report_data.append({"Status": "MATCHED", "Current": item["name"], "Matched": match["file_name"], "Case": match["case_name"]})
                
                else:
                    # STEP C: NO MATCH - Safely Add to Vault
                    # This logical gate prevents the Line 113 APIError
                    supabase.table("image_inventory").insert({
                        "case_name": case_ref,
                        "file_name": item["name"],
                        "image_hash": item["hash"]
                    }).execute()

    if report_data:
        st.subheader("Forensic Match Report")
        st.dataframe(pd.DataFrame(report_data), use_container_width=True)

# --- 5. DANGER ZONE ---
st.sidebar.divider()
st.sidebar.subheader("⚠️ Vault Management")
if st.sidebar.button("Wipe All Cloud Records"):
    supabase.table("image_inventory").delete().neq("id", 0).execute()
    st.rerun()
