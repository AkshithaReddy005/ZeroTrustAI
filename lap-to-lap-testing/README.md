# Laptop-to-Laptop Testing Setup

This folder contains the separated laptop-to-laptop testing files to avoid merge conflicts with the main dashboard integration code.

## Structure

- `detector/` - Modified detector code for lap-to-lap testing
- `scripts/` - Test scripts for cross-laptop attacks
- `docs/` - Documentation and connection status

## Key Differences from Main Code

1. **Detector IP**: Configured for cross-laptop testing (192.168.137.222)
2. **Test Scripts**: Updated to target remote detector IP
3. **Model Loading**: Uses simplified models for false positive fixes
4. **Thresholds**: Adjusted anomaly thresholds (0.8) to reduce false positives

## Usage

1. Start detector on detector laptop:
   ```bash
   cd lap-to-lap-testing/detector
   python main.py
   ```

2. Run attacks from attacker laptop:
   ```bash
   cd lap-to-lap-testing/scripts
   python test_detector.py
   python api_attacker.py
   ```

## IP Configuration

- Detector laptop: 192.168.137.222
- Attacker laptop: 192.168.137.171

Update these IPs in the scripts if your network configuration changes.
