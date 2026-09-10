#!/usr/bin/env swift
// Renders the ReportMate fleet app icon: a rounded blue tile with a bar chart
// and a check mark, at every size the iconset needs. Run by build-app.sh
// when Sources/ReportMateMac/Resources/AppIcon.icns is missing.
//
//   swift scripts/make-app-icon.swift <output.icns>

import AppKit

let output = CommandLine.arguments.dropFirst().first ?? "AppIcon.icns"
let iconset = FileManager.default.temporaryDirectory.appendingPathComponent("ReportMateIcon-\(UUID().uuidString).iconset")
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

func render(_ size: CGFloat) -> NSImage {
    let image = NSImage(size: NSSize(width: size, height: size))
    image.lockFocus()
    let s = size
    let inset = s * 0.06
    let tile = NSBezierPath(roundedRect: NSRect(x: inset, y: inset, width: s - inset * 2, height: s - inset * 2), xRadius: s * 0.22, yRadius: s * 0.22)
    let gradient = NSGradient(colors: [NSColor(calibratedRed: 0.20, green: 0.52, blue: 0.98, alpha: 1), NSColor(calibratedRed: 0.10, green: 0.30, blue: 0.80, alpha: 1)])!
    gradient.draw(in: tile, angle: -60)
    // Bars: three columns rising left to right.
    let barWidth = s * 0.14, gap = s * 0.06, baseY = s * 0.28
    let heights: [CGFloat] = [0.22, 0.34, 0.46]
    let totalWidth = barWidth * 3 + gap * 2
    var x = (s - totalWidth) / 2
    NSColor.white.withAlphaComponent(0.92).setFill()
    for h in heights {
        NSBezierPath(roundedRect: NSRect(x: x, y: baseY, width: barWidth, height: s * h), xRadius: s * 0.025, yRadius: s * 0.025).fill()
        x += barWidth + gap
    }
    // Check badge in the top-right corner.
    let badge = s * 0.30
    let badgeRect = NSRect(x: s - inset - badge - s * 0.05, y: s - inset - badge - s * 0.05, width: badge, height: badge)
    NSColor(calibratedRed: 0.16, green: 0.72, blue: 0.45, alpha: 1).setFill()
    NSBezierPath(ovalIn: badgeRect).fill()
    let check = NSBezierPath()
    check.lineWidth = badge * 0.14
    check.lineCapStyle = .round
    check.lineJoinStyle = .round
    check.move(to: NSPoint(x: badgeRect.minX + badge * 0.27, y: badgeRect.minY + badge * 0.50))
    check.line(to: NSPoint(x: badgeRect.minX + badge * 0.44, y: badgeRect.minY + badge * 0.33))
    check.line(to: NSPoint(x: badgeRect.minX + badge * 0.74, y: badgeRect.minY + badge * 0.66))
    NSColor.white.setStroke()
    check.stroke()
    image.unlockFocus()
    return image
}

func write(_ image: NSImage, size: Int, scale: Int) throws {
    let pixels = size * scale
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: size, height: size)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    image.draw(in: NSRect(x: 0, y: 0, width: size, height: size), from: .zero, operation: .sourceOver, fraction: 1)
    NSGraphicsContext.restoreGraphicsState()
    let name = scale == 1 ? "icon_\(size)x\(size).png" : "icon_\(size)x\(size)@2x.png"
    try rep.representation(using: .png, properties: [:])!.write(to: iconset.appendingPathComponent(name))
}

for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] { try write(render(CGFloat(size * scale)), size: size, scale: scale) }
}
let task = Process()
task.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
task.arguments = ["-c", "icns", iconset.path, "-o", output]
try task.run()
task.waitUntilExit()
try? FileManager.default.removeItem(at: iconset)
guard task.terminationStatus == 0 else { exit(1) }
print("Wrote \(output)")
