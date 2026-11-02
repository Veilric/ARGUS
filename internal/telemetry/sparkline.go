package telemetry

import (
	"strings"
	"sync"
	"time"
)

var sparkBlocks = []rune{' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// RingBuffer stores recent latency samples for sparkline rendering and metrics.
type RingBuffer struct {
	mu       sync.RWMutex
	capacity int
	samples  []float64 // latency in ms (-1 indicates timeout/drop)
	head     int
	count    int
}

func NewRingBuffer(capacity int) *RingBuffer {
	return &RingBuffer{
		capacity: capacity,
		samples:  make([]float64, capacity),
	}
}

func (rb *RingBuffer) Push(val float64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.samples[rb.head] = val
	rb.head = (rb.head + 1) % rb.capacity
	if rb.count < rb.capacity {
		rb.count++
	}
}

// Stats returns min, max, average, and loss percentage.
func (rb *RingBuffer) Stats() (min float64, max float64, avg float64, lossPercent float64) {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.count == 0 {
		return 0, 0, 0, 0
	}

	var sum float64
	validCount := 0
	droppedCount := 0
	min = -1
	max = -1

	for i := 0; i < rb.count; i++ {
		idx := (rb.head - 1 - i + rb.capacity) % rb.capacity
		val := rb.samples[idx]
		if val < 0 {
			droppedCount++
		} else {
			if min < 0 || val < min {
				min = val
			}
			if max < 0 || val > max {
				max = val
			}
			sum += val
			validCount++
		}
	}

	lossPercent = (float64(droppedCount) / float64(rb.count)) * 100.0
	if validCount > 0 {
		avg = sum / float64(validCount)
	}
	if min < 0 {
		min = 0
	}
	if max < 0 {
		max = 0
	}
	return min, max, avg, lossPercent
}

// RenderSparkline converts buffered latency samples into a Unicode sparkline.
func (rb *RingBuffer) RenderSparkline(width int) string {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.count == 0 || width <= 0 {
		return strings.Repeat("·", width)
	}

	if width > rb.count {
		width = rb.count
	}

	// Extract last `width` samples in chronological order
	window := make([]float64, width)
	for i := 0; i < width; i++ {
		idx := (rb.head - width + i + rb.capacity) % rb.capacity
		window[i] = rb.samples[idx]
	}

	// Find min and max among valid samples
	var maxVal float64 = 1.0
	for _, v := range window {
		if v > maxVal {
			maxVal = v
		}
	}

	var sb strings.Builder
	for _, v := range window {
		if v < 0 {
			sb.WriteString("✗") // dropped packet indicator
		} else {
			ratio := v / maxVal
			bIdx := int(ratio * float64(len(sparkBlocks)-1))
			if bIdx < 0 {
				bIdx = 0
			}
			if bIdx >= len(sparkBlocks) {
				bIdx = len(sparkBlocks) - 1
			}
			sb.WriteRune(sparkBlocks[bIdx])
		}
	}

	return sb.String()
}

// LatencySample combines measurement and timestamp.
type LatencySample struct {
	Target    string
	Duration  time.Duration
	Success   bool
	Timestamp time.Time
}
