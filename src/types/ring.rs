use std::slice;
use std::iter::FusedIterator;

/// Circular list of N elements.
///
/// Pushing new element in ring that exceed its capacity overwrites the oldest element in
/// the Ring.
///
/// Provides read-only access to elements through Iterator interface.
pub struct Ring<T> {
    buffer: Vec<T>,
    /// Once `buffer` gets all N elements, `oldest_ind` becomes Some(0), and increments every time
    /// new element pushed
    oldest_ind: Option<usize>,
}

impl<T> Ring<T> {
    /// Instantiates a ring of `capacity` elements.
    ///
    /// # Panic
    /// Panics if `capacity == 0`
    pub fn new(capacity: usize) -> Self {
        assert_ne!(capacity, 0, "ring capacity must be positive");
        Self {
            buffer: Vec::with_capacity(capacity),
            oldest_ind: None,
        }
    }

    pub fn push(&mut self, value: T) {
        match self.oldest_ind {
            Some(i) => {
                self.buffer[i] = value;
                self.oldest_ind = if i + 1 == self.buffer.len() { Some(0) } else { Some(i + 1) };
            }
            None => {
                self.buffer.push(value);
                if self.buffer.len() == self.buffer.capacity() {
                    self.oldest_ind = Some(0);
                }
            }
        }
    }

    pub fn iter(&self) -> RingIter<T> {
        match self.oldest_ind {
            None | Some(0) => RingIter {
                right_side: self.buffer.iter(),
                left_side: None,
            },
            Some(n) => RingIter {
                right_side: self.buffer[n..].iter(),
                left_side:  Some(self.buffer[..n].iter()),
            },
        }
    }

    pub fn first(&self) -> Option<&T> {
        match self.oldest_ind {
            Some(n) => Some(&self.buffer[n]),
            None => self.buffer.first(),
        }
    }
}

pub struct RingIter<'a, T> {
    right_side: slice::Iter<'a, T>,
    left_side:  Option<slice::Iter<'a, T>>,
}

impl<'a, T> Iterator for RingIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        if let Some(x) = self.right_side.next() {
            return Some(x)
        }
        match self.left_side.take() {
            Some(side) => {
                self.right_side = side;
                self.left_side = None;
                self.right_side.next()
            }
            None => None,
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = <Self as ExactSizeIterator>::len(self);
        (size, Some(size))
    }
}

impl<'a, T> FusedIterator for RingIter<'a, T> {}

impl<'a, T> DoubleEndedIterator for RingIter<'a, T> {
    fn next_back(&mut self) -> Option<&'a T> {
        if let Some(s) = self.left_side.as_mut().and_then(|s| s.next_back()) {
            Some(s)
        } else {
            self.right_side.next_back()
        }
    }
}

impl<'a, T> ExactSizeIterator for RingIter<'a, T> {
    fn len(&self) -> usize {
        self.right_side.as_slice().len()
            + self.left_side.as_ref().map(|s| s.as_slice().len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn accept_less_than_n_elems_and_gives_them_back() {
        let mut ring = Ring::new(3);
        ring.push(1);
        ring.push(2);

        assert!(ring.iter().cloned().eq(vec![1, 2]));
    }

    #[test]
    fn accepts_exactly_n_elems_and_gives_them_back() {
        let mut ring = Ring::new(3);
        ring.push(1);
        ring.push(2);
        ring.push(3);

        assert!(ring.iter().cloned().eq(vec![1, 2, 3]));
    }

    #[test]
    fn accepts_more_than_n_elems_and_gives_back_only_last_n_of_them() {
        let mut ring = Ring::new(3);
        ring.push(1);
        ring.push(2);
        ring.push(3);
        ring.push(4);
        ring.push(5);

        assert!(ring.iter().cloned().eq(vec![3, 4, 5]));
    }
}
