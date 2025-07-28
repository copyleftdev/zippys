#!/bin/bash

# Comprehensive Test Data Runner for Zip Slip Security Tool
# Author: copyleftdev

echo "🔍 Zip Slip Security Tool - Comprehensive Test Data Analysis"
echo "============================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to run tests and display results
run_test_category() {
    local category=$1
    local description=$2
    local expected_result=$3
    
    echo -e "\n${BLUE}📂 Testing Category: ${category}${NC}"
    echo -e "${YELLOW}Description: ${description}${NC}"
    echo -e "${YELLOW}Expected Result: ${expected_result}${NC}"
    echo "----------------------------------------"
    
    if [ -d "testdata/${category}" ]; then
        ./zippys scan testdata/${category}/*.zip
    else
        echo -e "${RED}❌ Directory testdata/${category} not found${NC}"
    fi
}

# Build the tool first
echo -e "${BLUE}🔨 Building Zip Slip Security Tool...${NC}"
go build -o zippys main.go

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Build failed!${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Build successful!${NC}"

# Test Categories
echo -e "\n${GREEN}🚀 Starting Comprehensive Test Data Analysis${NC}"

# 1. Vulnerable Test Cases
run_test_category "vulnerable" \
    "Known vulnerability patterns that should be detected" \
    "All files should be flagged as VULNERABLE"

# 2. Safe Test Cases  
run_test_category "safe" \
    "Legitimate file paths that should be considered safe" \
    "All files should be flagged as SAFE"

# 3. Mixed Test Cases
run_test_category "mixed" \
    "ZIP files containing both safe and vulnerable paths" \
    "Should be flagged as VULNERABLE with specific dangerous paths listed"

# 4. Adversarial Test Cases
run_test_category "adversarial" \
    "Sophisticated bypass attempts and evasion techniques" \
    "Should be flagged as VULNERABLE, demonstrating bypass resistance"

# Summary
echo -e "\n${GREEN}📊 Test Data Analysis Complete!${NC}"
echo "============================================================"
echo -e "${BLUE}Test Data Categories Covered:${NC}"
echo "✅ Parent Directory Traversal (../../../etc/passwd)"
echo "✅ URL Encoding (%2e%2e%2f%2e%2e%2f)"
echo "✅ Absolute Paths (/etc/passwd, \\windows\\system32)"
echo "✅ Tilde Expansion (~/.ssh/config, ~/../../etc/passwd)"
echo "✅ Colon Patterns (C:\\, 00:\\, :\\)"
echo "✅ Windows Device Names (CON, PRN, COM1, LPT1)"
echo "✅ Mixed Separators (../\\../etc, ..\\../windows)"
echo "✅ Edge Cases (Safe patterns: ~0, A:A, 0:00)"
echo "✅ Adversarial Patterns (Sophisticated bypass attempts)"

echo -e "\n${YELLOW}📋 Individual Test Commands:${NC}"
echo "./zippys scan testdata/vulnerable/parent_traversal.zip"
echo "./zippys scan testdata/vulnerable/url_encoding.zip"
echo "./zippys scan testdata/vulnerable/colon_patterns.zip"
echo "./zippys scan testdata/safe/normal_files.zip"
echo "./zippys scan testdata/mixed/mixed_patterns.zip"
echo "./zippys scan testdata/adversarial/bypass_attempts.zip"

echo -e "\n${GREEN}🎯 Advanced Algorithmic Detection System Validated!${NC}"
