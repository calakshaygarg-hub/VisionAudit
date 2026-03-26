import streamlit as st
import pdfplumber
import imagehash
from PIL import Image
import pandas as pd
from supabase import create_client, Client

# --- 1. CONFIG & CONNECTION ---
st.set_page_config(page_title="VisionAudit Cloud", layout="wide")
supabase: Client = create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])

# ... (Insert your check_password() function here) ...

st.title("🔍 VisionAudit: Categorized Forensic Vault")

# --- 2. AUDIT SETTINGS ---
with st.sidebar:
    case_ref = st.text_input("Case Reference / Client", "General Audit")
    uploaded_files = st.file_uploader("Upload Invoices/PDFs", type=["pdf", "png", "jpg"], accept_multiple_files=True)
    if st.button("Wipe Cloud Vault"):
        supabase.table("image_inventory").delete().neq("id", 0).execute()
        st.rerun()

if uploaded_files:
    # Storage for sorted matches
    cat_diff_file = []
    cat_same_file_diff_page = []
    cat_same_page = []

    for uploaded_file in uploaded_files:
        current_file_images = []
        
        # Extraction logic
        if uploaded_file.type == "application/pdf":
            with pdfplumber.open(uploaded_file) as pdf:
                for i, page in enumerate(pdf.pages):
                    for img_idx, img in enumerate(page.images):
                        try:
                            page_obj = page.crop((img["x0"], img["top"], img["x1"], img["bottom"]))
                            pil_img = page_obj.to_image(resolution=150).original
                            h_str = str(imagehash.phash(pil_img))
                            current_file_images.append({
                                "name": uploaded_file.name,
                                "page": i + 1,
                                "img_idx": img_idx + 1,
                                "img": pil_img,
                                "hash": h_str
                            })
                        except: continue
        else:
            pil_img = Image.open(uploaded_file)
            h_str = str(imagehash.phash(pil_img))
            current_file_images.append({"name": uploaded_file.name, "page": 1, "img_idx": 1, "img": pil_img, "hash": h_str})

        # --- 3. THE FORENSIC SORTING ENGINE ---
        for item in current_file_images:
            # Query the vault for this fingerprint
            res = supabase.table("image_inventory").select("*").eq("image_hash", item["hash"]).execute()
            
            if res.data:
                for match in res.data:
                    match_data = {"new": item, "old": match}
                    
                    # CATEGORY 1: Different Files
                    if match["file_name"] != item["name"]:
                        cat_diff_file.append(match_data)
                    
                    # CATEGORY 2: Same File, Different Pages
                    elif match["file_name"] == item["name"] and match["page_number"] != item["page"]:
                        cat_same_file_diff_page.append(match_data)
                        
                    # CATEGORY 3: Same File, Same Page (e.g. same logo appearing twice on one page)
                    elif match["file_name"] == item["name"] and match["page_number"] == item["page"]:
                        cat_same_page.append(match_data)
            else:
                # No match found? Safe to index.
                supabase.table("image_inventory").insert({
                    "case_name": case_ref,
                    "file_name": item["name"],
                    "page_number": item["page"],
                    "image_hash": item["hash"]
                }).execute()

    # --- 4. CATEGORIZED TAB DISPLAY ---
    t1, t2, t3 = st.tabs([
        "📁 Match: Different Files", 
        "📄 Match: Same File (Diff Pages)", 
        "📍 Match: Same Page"
    ])

    def display_match(match_list, tab_obj):
        with tab_obj:
            if not match_list:
                st.info("No duplicates found in this category.")
            for m in match_list:
                with st.expander(f"Match found in {m['old']['file_name']}", expanded=True):
                    c1, c2 = st.columns(2)
                    with c1:
                        st.caption(f"New: {m['new']['name']} (Pg {m['new']['page']})")
                        st.image(m['new']['img'], use_container_width=True)
                    with c2:
                        st.caption(f"Vault: {m['old']['file_name']} (Pg {m['old']['page_number']})")
                        st.image(m['new']['img'], use_container_width=True) # visual comparison

    display_match(cat_diff_file, t1)
    display_match(cat_same_file_diff_page, t2)
    display_match(cat_same_page, t3)
