import sys
import matplotlib.pylab as plt
import json
import math
import numpy as np
import warnings
from matplotlib.backends.backend_pdf import PdfPages
#from scipy import stats
from matplotlib.patches import Polygon
import Statistics as stats

s = stats.Statistics()


k1 = [474, 593, 548, 455, 517, 496, 539, 513, 496, 502, 583, 503, 487, 524, 531, 465, 478, 509, 484, 510, 512, 512, 479, 525, 486, 510, 522, 494, 462, 533, 482, 496, 515, 479, 539, 479, 539, 528, 525, 564, 555, 455, 505, 463, 529, 520, 499, 492, 530, 456, 452, 503, 538, 464, 530, 453, 511, 505, 418, 520, 401, 514, 491, 575, 485, 497, 499, 433, 477, 482, 467, 554, 473, 538, 488, 499, 526, 502, 493, 502, 506, 541, 497, 530, 493, 497, 471, 490, 472, 528, 507, 500, 480, 508, 548, 518, 495, 473, 523, 512, 469, 473, 551, 501, 500, 469, 493, 556, 507, 424, 508, 585, 563, 483, 473, 491, 481, 490, 453, 422, 510, 548, 498, 523, 478, 521, 548, 525, 486, 552, 508, 514, 479, 510, 508, 452, 543, 442, 534, 524, 463, 497, 457, 525, 509, 553, 553, 558, 566, 503, 456, 526, 466, 520, 531, 408, 532, 608, 514, 525, 480, 451, 517, 490, 451, 499, 513, 520, 503, 597, 528, 513, 511, 396, 448, 404, 526, 471, 509, 462, 544, 516, 535, 472, 475, 475, 551, 482, 537, 475, 488, 487, 480, 505, 464, 482, 492, 504, 506, 485, 496, 513, 425, 575, 525, 507, 523, 494, 475, 540, 493, 539, 533, 556, 473, 509, 540, 482, 470, 457, 480, 539, 570, 457, 493, 501, 522, 516, 496, 475, 526, 434, 578, 550, 479, 494, 525, 439, 495, 439, 544, 489, 430, 563, 505, 481, 540, 520, 484, 556, 543, 556, 515, 513, 500, 531, 557, 478, 507, 473, 434, 501, 543, 529, 471, 508, 539, 476, 470, 457, 533, 492, 540, 511, 461, 489, 524, 547, 503, 487, 466, 533, 432, 504, 480, 501, 494, 493, 564, 534, 591, 504, 504, 517, 569, 507, 476, 514, 486, 520, 486, 514, 489, 539, 541, 494, 447, 520, 485, 491, 523, 496, 539, 498, 534, 519, 495, 496, 457, 465, 557, 578, 482, 517, 525, 479, 503, 490, 543, 583, 532, 573, 495]

k2 = [257, 277, 224, 259, 227, 216, 241, 220, 225, 263, 218, 250, 246, 270, 258, 259, 248, 290, 264, 247, 287, 190, 247, 227, 241, 268, 250, 267, 262, 253, 266, 294, 286, 277, 196, 287, 224, 273, 277, 240, 242, 247, 200, 258, 202, 254, 231, 266, 238, 237, 232, 272, 219, 190, 183, 226, 273, 223, 208, 233, 242, 278, 268, 223, 226, 248, 227, 281, 278, 240, 259, 234, 267, 250, 240, 253, 258, 292, 237, 229, 274, 283, 233, 259, 234, 239, 207, 242, 237, 261, 228, 266, 246, 283, 261, 281, 198, 299, 247, 219, 267, 233, 243, 257, 251, 216, 235, 209, 201, 200, 202, 270, 212, 271, 288, 238, 251, 264, 264, 260, 250, 225, 241, 204, 289, 239, 250, 280, 309, 273, 245, 283, 297, 256, 211, 221, 251, 226, 252, 271, 211, 248, 279, 273, 238, 248, 222, 274, 273, 282, 237, 253, 251, 224, 215, 267, 246, 219, 268, 265, 199, 272, 255, 253, 261, 290, 224, 249, 283, 257, 214, 255, 301, 242, 248, 253, 246, 218, 222, 221, 270, 242, 219, 227, 221, 304, 233, 259, 218, 270, 262, 237, 211, 257, 281, 250, 249, 233, 274, 263, 273, 217, 261, 230, 265, 222, 237, 245, 265, 247, 216, 286, 256, 239, 260, 264, 275, 241, 242, 286, 260, 232, 248, 221, 234, 235, 203, 298, 295, 275, 280, 225, 280, 261, 175, 269, 245, 291, 242, 255, 199, 189, 248, 263, 263, 227, 217, 255, 237, 305, 266, 235, 304, 228, 247, 245, 237, 233, 258, 267, 226, 293, 265, 257, 253, 271, 240, 271, 248, 272, 270, 272, 226, 281, 254, 225, 228, 292, 304, 245, 231, 269, 265, 291, 259, 198, 250, 272, 270, 209, 273, 232, 228, 261, 291, 198, 219, 233, 267, 228, 254, 233, 309, 221, 303, 268, 234, 215, 271, 223, 250, 243, 218, 264, 254, 267, 274, 249, 238, 232, 229, 263, 248, 211, 260, 236, 284, 282, 201, 220, 220, 255, 265]

k3 = [103, 99, 124, 123, 116, 119, 104, 123, 80, 145, 141, 131, 124, 135, 120, 144, 139, 120, 131, 136, 132, 139, 124, 140, 164, 100, 163, 137, 128, 138, 163, 81, 127, 144, 118, 104, 98, 142, 112, 123, 157, 140, 107, 136, 123, 147, 161, 110, 138, 120, 123, 122, 137, 138, 108, 172, 175, 135, 115, 128, 123, 89, 124, 100, 100, 110, 107, 123, 150, 136, 98, 128, 149, 129, 94, 125, 151, 136, 142, 133, 122, 141, 137, 161, 91, 142, 131, 129, 139, 142, 139, 149, 111, 123, 112, 94, 131, 124, 122, 109, 101, 113, 150, 113, 111, 134, 122, 148, 122, 156, 88, 106, 114, 170, 117, 166, 135, 144, 142, 122, 115, 115, 127, 125, 132, 177, 122, 124, 122, 117, 112, 118, 141, 156, 124, 135, 130, 146, 125, 116, 99, 127, 143, 117, 99, 103, 113, 114, 89, 129, 157, 126, 94, 148, 117, 132, 132, 131, 121, 138, 145, 132, 130, 81, 113, 130, 121, 163, 161, 136, 121, 137, 106, 128, 123, 121, 113, 118, 165, 96, 105, 112, 129, 129, 112, 164, 133, 124, 114, 116, 107, 126, 139, 144, 144, 124, 152, 115, 127, 137, 123, 124, 126, 123, 119, 147, 123, 135, 124, 108, 138, 68, 127, 113, 122, 136, 98, 122, 114, 113, 140, 98, 109, 84, 125, 106, 135, 111, 117, 119, 82, 87, 115, 112, 129, 157, 112, 132, 113, 140, 118, 85, 96, 139, 102, 101, 153, 140, 96, 139, 143, 140, 126, 131, 119, 180, 140, 107, 139, 118, 116, 121, 122, 128, 100, 165, 136, 140, 131, 103, 100, 104, 126, 123, 108, 127, 137, 135, 137, 130, 108, 88, 125, 132, 125, 130, 128, 133, 108, 150, 138, 96, 115, 120, 155, 117, 121, 78, 133, 120, 90, 98, 116, 143, 104, 128, 148, 121, 125, 150, 135, 128, 165, 150, 152, 77, 97, 94, 98, 133, 135, 114, 106, 138, 113, 128, 114, 130, 127, 129, 125, 119, 131]

k4 = [77, 58, 57, 56, 46, 87, 68, 75, 57, 61, 73, 74, 65, 62, 66, 53, 60, 79, 61, 88, 66, 70, 66, 52, 67, 59, 91, 46, 31, 60, 58, 60, 63, 54, 58, 95, 84, 61, 60, 56, 98, 37, 59, 91, 44, 76, 80, 79, 49, 91, 63, 57, 65, 56, 83, 55, 65, 49, 63, 48, 58, 63, 75, 74, 66, 41, 70, 41, 91, 71, 56, 78, 91, 61, 45, 66, 68, 54, 77, 85, 55, 66, 54, 61, 52, 109, 65, 53, 50, 62, 87, 66, 49, 51, 100, 62, 43, 64, 66, 60, 64, 77, 64, 67, 67, 60, 45, 72, 33, 62, 65, 53, 56, 69, 53, 55, 58, 54, 59, 56, 63, 47, 64, 58, 62, 54, 64, 64, 28, 80, 56, 51, 78, 72, 55, 60, 46, 60, 59, 80, 81, 90, 57, 60, 38, 50, 108, 52, 76, 64, 43, 60, 51, 47, 49, 84, 78, 28, 53, 73, 86, 82, 55, 67, 51, 77, 67, 68, 60, 74, 66, 63, 61, 47, 76, 47, 55, 69, 62, 65, 53, 59, 60, 43, 46, 76, 68, 60, 91, 52, 38, 90, 59, 75, 67, 61, 62, 62, 49, 57, 52, 64, 54, 80, 79, 63, 75, 62, 48, 44, 54, 60, 53, 60, 51, 57, 81, 51, 61, 64, 75, 59, 59, 50, 62, 84, 51, 69, 51, 71, 45, 59, 70, 43, 54, 53, 60, 62, 57, 55, 83, 64, 59, 52, 44, 80, 58, 81, 74, 36, 68, 66, 52, 54, 55, 91, 68, 70, 52, 76, 47, 81, 38, 50, 79, 57, 65, 56, 49, 81, 76, 64, 54, 63, 105, 56, 69, 74, 55, 65, 63, 57, 41, 90, 63, 67, 74, 66, 50, 54, 38, 52, 45, 67, 77, 58, 74, 72, 61, 74, 67, 71, 73, 54, 52, 61, 78, 75, 61, 54, 45, 68, 52, 60, 87, 48, 45, 74, 67, 60, 57, 45, 61, 68, 43, 81, 74, 74, 84, 71, 67, 72, 57]

k5 = [40, 35, 38, 37, 37, 36, 29, 50, 37, 33, 35, 22, 35, 32, 46, 18, 32, 42, 32, 30, 44, 21, 19, 36, 39, 46, 34, 26, 21, 46, 28, 32, 15, 38, 42, 25, 37, 24, 34, 25, 17, 29, 43, 27, 41, 58, 43, 32, 54, 24, 22, 46, 27, 32, 30, 18, 20, 20, 30, 24, 28, 30, 30, 34, 30, 25, 23, 34, 31, 24, 36, 35, 22, 31, 24, 42, 22, 29, 58, 46, 25, 62, 37, 41, 33, 23, 28, 36, 26, 35, 29, 33, 31, 29, 37, 32, 43, 34, 20, 35, 50, 37, 31, 26, 20, 23, 30, 32, 26, 48, 40, 28, 21, 43, 25, 35, 24, 29, 39, 25, 29, 27, 33, 25, 29, 37, 22, 24, 39, 38, 43, 22, 26, 22, 41, 28, 19, 38, 31, 28, 29, 30, 33, 51, 37, 19, 43, 22, 25, 41, 39, 35, 26, 19, 25, 42, 23, 24, 33, 27, 16, 29, 28, 37, 30, 22, 28, 17, 20, 22, 35, 21, 15, 47, 38, 35, 37, 35, 32, 48, 23, 35, 39, 31, 45, 31, 26, 30, 38, 29, 31, 33, 33, 30, 54, 24, 30, 41, 32, 32, 46, 21, 39, 36, 28, 55, 30, 32, 37, 24, 23, 27, 28, 24, 34, 27, 18, 46, 37, 39, 34, 41, 24, 40, 34, 22, 27, 42, 34, 37, 35, 20, 36, 39, 21, 35, 33, 15, 27, 33, 50, 56, 29, 41, 29, 20, 30, 21, 28, 42, 23, 25, 23, 37, 23, 25, 16, 48, 36, 40, 23, 31, 27, 34, 33, 27, 38, 27, 31, 27, 23, 24, 45, 38, 40, 35, 44, 38, 29, 42, 25, 40, 39, 27, 23, 36, 27, 29, 21, 28, 27, 35, 26, 31, 25, 30, 25, 34, 25, 40, 30, 31, 24, 30, 41, 27, 36, 35, 23, 25, 32, 47, 25, 27, 42, 34, 22, 26, 34, 35, 45, 34, 30, 23, 22, 30, 23, 35, 42, 35, 31, 41, 39]

k6 = [17, 12, 19, 8, 12, 27, 14, 20, 11, 15, 15, 12, 21, 16, 9, 17, 15, 13, 8, 14, 6, 10, 23, 15, 24, 9, 7, 7, 22, 20, 15, 10, 13, 13, 22, 21, 23, 14, 12, 13, 27, 12, 19, 12, 15, 10, 14, 18, 16, 17, 14, 13, 17, 19, 13, 28, 18, 32, 12, 13, 23, 14, 19, 11, 12, 35, 10, 8, 15, 7, 11, 9, 23, 28, 11, 21, 15, 8, 13, 11, 10, 26, 17, 16, 19, 30, 19, 23, 11, 15, 18, 16, 14, 17, 22, 26, 17, 17, 13, 12, 16, 19, 24, 21, 9, 18, 14, 15, 18, 13, 12, 17, 16, 17, 16, 9, 12, 15, 17, 19, 26, 9, 19, 14, 18, 14, 19, 16, 15, 10, 23, 21, 15, 16, 19, 18, 12, 12, 8, 19, 19, 15, 16, 31, 15, 9, 16, 14, 13, 18, 13, 19, 18, 22, 18, 15, 13, 10, 13, 7, 13, 7, 7, 13, 20, 16, 17, 8, 6, 11, 13, 20, 12, 28, 20, 13, 19, 13, 13, 10, 16, 15, 20, 12, 10, 13, 16, 15, 18, 23, 12, 22, 13, 6, 13, 21, 28, 11, 10, 15, 21, 19, 17, 17, 16, 20, 20, 13, 17, 16, 12, 21, 10, 19, 13, 17, 8, 12, 11, 15, 23, 20, 6, 11, 14, 7, 14, 30, 12, 9, 16, 15, 20, 9, 23, 9, 11, 17, 13, 21, 18, 17, 8, 23, 6, 13, 8, 22, 14, 31, 13, 25, 9, 18, 20, 9, 23, 3, 22, 12, 18, 19, 7, 23, 16, 21, 16, 31, 22, 20, 17, 20, 17, 21, 15, 8, 14, 16, 8, 19, 12, 11, 15, 18, 21, 3, 30, 25, 7, 16, 16, 8, 17, 15, 29, 22, 31, 14, 12, 23, 34, 10, 23, 20, 15, 15, 12, 26, 20, 21, 15, 9, 18, 13, 6, 13, 23, 14, 10, 22, 36, 16, 13, 28, 6, 14, 16, 8, 22, 20, 16, 10, 14]

k7 = [5, 8, 10, 12, 12, 11, 12, 8, 4, 5, 7, 14, 14, 9, 3, 3, 11, 12, 9, 14, 6, 11, 7, 12, 10, 4, 3, 5, 11, 2, 12, 5, 6, 17, 8, 8, 7, 9, 14, 9, 7, 6, 10, 6, 8, 4, 6, 6, 11, 4, 4, 6, 4, 14, 9, 4, 9, 8, 12, 8, 9, 8, 3, 9, 3, 3, 10, 7, 7, 15, 6, 12, 4, 19, 11, 7, 7, 10, 5, 5, 8, 15, 15, 6, 12, 12, 5, 7, 12, 8, 5, 6, 11, 6, 3, 12, 8, 5, 4, 2, 8, 11, 16, 10, 4, 15, 9, 10, 6, 10, 5, 7, 8, 5, 15, 12, 3, 5, 6, 8, 9, 9, 7, 14, 14, 6, 8, 9, 6, 15, 7, 2, 7, 11, 3, 8, 5, 8, 7, 6, 6, 14, 1, 11, 11, 7, 11, 3, 13, 6, 4, 7, 2, 8, 5, 6, 3, 3, 5, 5, 10, 5, 6, 7, 6, 8, 7, 13, 9, 6, 13, 9, 7, 7, 6, 15, 6, 12, 5, 8, 14, 6, 8, 10, 8, 14, 5, 9, 11, 5, 5, 6, 2, 13, 5, 13, 4, 9, 6, 7, 7, 14, 22, 10, 15, 15, 9, 7, 27, 3, 0, 9, 4, 12, 13, 4, 12, 6, 4, 12, 13, 3, 23, 5, 9, 12, 9, 2, 12, 10, 7, 16, 6, 8, 13, 7, 6, 10, 4, 2, 3, 12, 10, 11, 7, 14, 5, 6, 6, 11, 8, 13, 8, 5, 3, 8, 6, 5, 17, 7, 4, 6, 8, 6, 11, 11, 12, 12, 11, 14, 13, 5, 3, 14, 4, 7, 3, 10, 11, 1, 9, 9, 9, 7, 3, 2, 6, 8, 5, 6, 8, 18, 8, 8, 6, 3, 10, 11, 9, 7, 11, 8, 9, 11, 4, 5, 15, 5, 10, 12, 3, 6, 10, 7, 14, 8, 9, 8, 9, 9, 8, 11, 7, 6, 3, 10, 4, 13, 9, 9, 8, 5, 8]

k8 = [3, 6, 0, 6, 5, 4, 5, 6, 1, 2, 7, 6, 1, 8, 10, 6, 3, 2, 1, 2, 4, 4, 1, 5, 2, 1, 11, 5, 5, 3, 6, 1, 4, 3, 0, 2, 6, 4, 3, 5, 5, 6, 1, 1, 1, 4, 8, 6, 5, 1, 2, 8, 2, 9, 13, 2, 6, 3, 4, 2, 7, 5, 3, 7, 2, 0, 8, 3, 2, 2, 1, 1, 4, 4, 7, 3, 9, 4, 6, 4, 9, 5, 3, 3, 4, 1, 5, 4, 5, 4, 6, 1, 6, 11, 3, 2, 8, 2, 2, 4, 10, 3, 11, 3, 3, 4, 3, 3, 2, 10, 3, 1, 2, 4, 11, 4, 3, 4, 7, 8, 2, 7, 3, 7, 6, 4, 4, 1, 6, 3, 1, 3, 5, 3, 5, 11, 2, 7, 1, 7, 8, 11, 4, 5, 2, 1, 5, 1, 4, 5, 1, 7, 3, 0, 3, 7, 9, 3, 9, 8, 5, 3, 1, 4, 4, 3, 5, 5, 8, 5, 6, 10, 4, 3, 3, 5, 3, 4, 5, 5, 6, 5, 3, 7, 4, 7, 5, 3, 2, 2, 7, 6, 6, 1, 7, 3, 1, 3, 7, 6, 3, 4, 5, 0, 2, 5, 5, 7, 2, 3, 1, 1, 1, 4, 6, 2, 4, 2, 4, 1, 3, 3, 7, 3, 0, 3, 0, 6, 3, 3, 1, 6, 4, 6, 2, 5, 3, 4, 1, 3, 3, 4, 10, 6, 2, 11, 0, 4, 7, 5, 3, 5, 4, 1, 10, 5, 2, 0, 4, 2, 11, 5, 9, 6, 5, 3, 4, 4, 4, 2, 7, 2, 7, 7, 3, 7, 4, 6, 5, 2, 5, 7, 7, 2, 3, 3, 8, 1, 6, 7, 4, 3, 4, 9, 2, 6, 9, 4, 3, 6, 2, 1, 7, 0, 8, 1, 3, 5, 4, 6, 2, 10, 7, 8, 2, 1, 3, 4, 8, 5, 2, 7, 4, 6, 3, 5, 8, 9, 7, 1, 2, 1, 5]

k9 = [5, 1, 2, 0, 3, 2, 3, 1, 1, 3, 2, 1, 2, 2, 3, 0, 4, 4, 0, 3, 3, 3, 0, 2, 2, 2, 5, 0, 0, 0, 2, 3, 2, 2, 0, 3, 1, 0, 3, 7, 0, 2, 2, 0, 2, 3, 3, 0, 0, 3, 9, 3, 6, 4, 2, 1, 1, 4, 2, 1, 4, 1, 2, 0, 1, 3, 1, 1, 3, 3, 2, 4, 0, 2, 4, 1, 2, 2, 1, 1, 0, 3, 6, 0, 3, 1, 1, 3, 2, 5, 3, 3, 2, 1, 1, 5, 0, 3, 0, 0, 2, 3, 3, 4, 3, 5, 2, 1, 3, 6, 7, 1, 2, 2, 3, 1, 1, 4, 1, 0, 5, 3, 0, 2, 1, 2, 3, 1, 0, 1, 4, 0, 3, 4, 2, 3, 3, 1, 4, 2, 0, 1, 3, 1, 3, 3, 1, 3, 4, 4, 2, 2, 2, 2, 3, 2, 0, 2, 2, 1, 4, 1, 2, 1, 1, 2, 2, 6, 0, 1, 2, 0, 6, 1, 2, 0, 3, 5, 2, 2, 1, 1, 3, 2, 2, 2, 3, 0, 0, 2, 3, 0, 5, 5, 5, 1, 0, 5, 1, 2, 2, 1, 1, 4, 4, 1, 1, 0, 3, 0, 1, 0, 2, 6, 2, 1, 1, 4, 0, 1, 2, 3, 2, 1, 1, 5, 0, 0, 2, 3, 3, 1, 1, 3, 2, 0, 1, 5, 2, 2, 1, 0, 0, 1, 2, 0, 2, 0, 4, 3, 3, 4, 2, 1, 4, 5, 3, 2, 2, 2, 2, 2, 4, 2, 1, 0, 3, 1, 0, 2, 1, 3, 1, 0, 2, 1, 3, 1, 1, 2, 3, 1, 3, 2, 1, 4, 0, 1, 3, 3, 2, 2, 1, 1, 8, 1, 2, 4, 0, 9, 0, 3, 3, 1, 1, 1, 6, 2, 2, 4, 1, 5, 0, 2, 0, 3, 1, 2, 3, 1, 2, 1, 3, 3, 0, 3, 3, 3, 0, 0, 10, 1, 0]

k = [3, 3, 0, 0, 0, 0, 0, 2, 0, 1, 0, 3, 0, 2, 1, 0, 1, 0, 3, 2, 0, 1, 1, 2, 0, 0, 0, 1, 3, 0, 2, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 2, 0, 0, 0, 2, 0, 2, 4, 3, 0, 0, 1, 0, 2, 2, 0, 2, 3, 0, 1, 0, 0, 0, 3, 0, 0, 3, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 2, 1, 4, 0, 1, 2, 0, 1, 4, 3, 2, 0, 2, 0, 0, 1, 2, 2, 1, 1, 0, 1, 3, 0, 3, 0, 2, 3, 0, 0, 1, 0, 1, 1, 1, 0, 1, 4, 2, 0, 5, 1, 1, 1, 0, 0, 6, 1, 1, 2, 1, 5, 2, 0, 1, 2, 0, 2, 2, 0, 0, 1, 2, 2, 1, 0, 2, 0, 3, 0, 1, 0, 1, 0, 0, 0, 3, 1, 1, 0, 2, 4, 0, 0, 1, 1, 3, 1, 3, 1, 0, 3, 2, 2, 2, 1, 1, 2, 4, 2, 1, 1, 4, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 2, 2, 2, 6, 0, 1, 0, 2, 1, 0, 1, 0, 3, 2, 1, 2, 4, 1, 1, 4, 1, 0, 1, 1, 0, 0, 4, 5, 0, 1, 0, 0, 0, 1, 1, 5, 1, 1, 0, 0, 0, 1, 4, 1, 2, 0, 6, 1, 2, 3, 2, 0, 2, 1, 1, 1, 4, 0, 2, 2, 1, 1, 2, 1, 0, 1, 1, 0, 2, 2, 1, 1, 1, 0, 1, 1, 2, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 2, 3, 1, 1, 0, 1, 0, 0, 1, 0, 0, 3, 0, 1, 0, 4, 1, 1, 0, 1, 2, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1]

print(len(k1))
print(len(k2))
print(len(k3))
print(len(k4))
print(len(k5))
print(len(k6))
print(len(k7))
print(len(k8))
print(len(k9))
print(len(k))
mediak1= s.getMean(k1)

errorbark1 = s.getConfidenceInterval(k1)


mediak2= s.getMean(k2)

errorbark2 = s.getConfidenceInterval(k2)

mediak3= s.getMean(k3)

errorbark3 = s.getConfidenceInterval(k3)

mediak4= s.getMean(k4)

errorbark4 = s.getConfidenceInterval(k4)

mediak5= s.getMean(k5)

errorbark5 = s.getConfidenceInterval(k5)

mediak6= s.getMean(k6)

errorbark6 = s.getConfidenceInterval(k6)

mediak7= s.getMean(k7)

errorbark7 = s.getConfidenceInterval(k7)

mediak8= s.getMean(k8)

errorbark8 = s.getConfidenceInterval(k8)

mediak9= s.getMean(k9)

errorbark9 = s.getConfidenceInterval(k9)

mediak= s.getMean(k)

errorbark = s.getConfidenceInterval(k)

medias=[mediak1, mediak2, mediak3, mediak4, mediak5, mediak6, mediak7, mediak8, mediak9, mediak]
mediaerr=[errorbark1,errorbark2,errorbark3,errorbark4,errorbark5,errorbark6,errorbark7,errorbark8,errorbark9,errorbark]

print(medias)
print(mediaerr)
a=['k=1', 'k=2', 'k=3', 'k=4', 'k=5', 'k=6', 'k=7', 'k=8', 'k=9', 'k=10']
plt.rc('xtick', labelsize=12) 
plt.rc('ytick', labelsize=12)
fig, ax = plt.subplots()
x=[1,2,3,4,5,6,7,8,9,10]
y=[1000*(0.5)**(float(i)) for i in x]
ax.plot(x,y, color='orange')

kwargs = dict(capsize=2, elinewidth=2, linewidth=1.8, ms=7)


ax.bar(x, medias, 0.35, yerr=mediaerr)


#ax.errorbar(x, medias, yerr=mediaerr, color='blue', ecolor='blue', fmt='-', mfc='blue', **kwargs, label='$J_E=N/2$')
#ax.legend(loc='best', frameon=True, fontsize=18)
ax.set_xlabel('# k hash fuctions', fontsize=18)
ax.set_ylabel('Judges per miner', fontsize=18)
ax.set_xticks(x)
plotfile = 'filtrobloomprova.pdf'
pp = PdfPages(plotfile)
pp.savefig()
pp.close()
plt.show()
plt.clf()
plt.cla()
plt.close()


