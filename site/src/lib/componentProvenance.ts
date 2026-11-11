import type { ComponentInventoryProducer, ComponentWithVulns } from '@/api/client'

export function inventoryProducerLabel(producer: ComponentInventoryProducer): string {
  return producer.engine ? `${producer.name} (${producer.engine})` : producer.name
}

export function inventoryProvenanceTitle(component: ComponentWithVulns): string[] {
  const producers = [...new Set((component.inventory_producers ?? []).map(inventoryProducerLabel))]
  const lines = producers.length ? [`Inventory producer: ${producers.join(', ')}`] : []
  if (component.inventory_sources?.length) lines.push(`Inventory documents: ${component.inventory_sources.join(', ')}`)
  return lines
}
