// readableTextColor picks black or white for text on an arbitrary background
// color, using WCAG relative luminance. Invalid input defaults to white text.
export function readableTextColor(background: string): string {
  const match = /^#([0-9a-f]{6})$/i.exec(background.trim())
  if (!match) {
    return '#ffffff'
  }
  const value = parseInt(match[1], 16)
  const channels = [(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff].map((channel) => {
    const scaled = channel / 255
    return scaled <= 0.03928 ? scaled / 12.92 : Math.pow((scaled + 0.055) / 1.055, 2.4)
  })
  const luminance = 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]
  return luminance > 0.4 ? '#0b0f14' : '#ffffff'
}
